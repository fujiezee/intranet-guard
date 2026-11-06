// Package notify 把新告警推送到企业微信 / 钉钉 / 飞书群机器人或通用 Webhook。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/store"
)

const (
	maxLines   = 20   // 单条消息最多列出的告警数
	maxContent = 3800 // 企业微信 markdown 上限 4096 字节，留出余量
)

var severityRank = map[model.Severity]int{model.SeverityLow: 0, model.SeverityMedium: 1, model.SeverityHigh: 2}
var severityLabel = map[model.Severity]string{model.SeverityLow: "低", model.SeverityMedium: "中", model.SeverityHigh: "高"}

// Filter 返回级别不低于 min 的告警。
func Filter(alerts []model.Alert, min model.Severity) []model.Alert {
	var out []model.Alert
	for _, a := range alerts {
		if severityRank[a.Severity] >= severityRank[min] {
			out = append(out, a)
		}
	}
	return out
}

func format(alerts []model.Alert) (title, text string) {
	high := 0
	for _, a := range alerts {
		if a.Severity == model.SeverityHigh {
			high++
		}
	}
	title = fmt.Sprintf("【内网防护】%d 条新告警", len(alerts))
	if high > 0 {
		title += fmt.Sprintf("（高危 %d）", high)
	}
	var b strings.Builder
	b.WriteString(title + "\n")
	for i, a := range alerts {
		line := fmt.Sprintf("\n- [%s] %s  %s", severityLabel[a.Severity], a.Message, a.CreatedAt.Local().Format("01-02 15:04:05"))
		if i >= maxLines || b.Len()+len(line) > maxContent {
			fmt.Fprintf(&b, "\n\n…另有 %d 条，请登录控制台查看", len(alerts)-i)
			break
		}
		b.WriteString(line)
	}
	return title, b.String()
}

// Send 按渠道类型构造告警消息并发送。
func Send(ctx context.Context, hc *http.Client, ch model.NotifyChannel, alerts []model.Alert) error {
	title, text := format(alerts)
	return SendMessage(ctx, hc, ch, title, text, map[string]any{"title": title, "alerts": alerts})
}

// SendMessage 发送一条 Markdown 文本消息（交接班、日报 / 周报）。通用 Webhook 收到的是 webhook 本身（JSON），
// 群机器人收到的是 text：企业微信、钉钉按 Markdown 显示，飞书按纯文本显示。
func SendMessage(ctx context.Context, hc *http.Client, ch model.NotifyChannel, title, text string, webhook any) error {
	target := ch.URL
	var body any
	switch ch.Type {
	case model.ChannelWeCom:
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": text}}
	case model.ChannelDingTalk:
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": title, "text": text}}
		if ch.Secret != "" {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			mac := hmac.New(sha256.New, []byte(ch.Secret))
			mac.Write([]byte(ts + "\n" + ch.Secret))
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target += sep + "timestamp=" + ts + "&sign=" + url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		}
	case model.ChannelFeishu:
		m := map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
		if ch.Secret != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			mac := hmac.New(sha256.New, []byte(ts+"\n"+ch.Secret)) // 飞书：以 timestamp\nsecret 为密钥签名空串
			m["timestamp"], m["sign"] = ts, base64.StdEncoding.EncodeToString(mac.Sum(nil))
		}
		body = m
	case model.ChannelWebhook:
		body = webhook
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %s: %s", resp.Status, truncate(string(respBody), 200))
	}
	// 群机器人即使配置错误（关键词、签名、IP 白名单）也返回 200，需要看业务错误码。
	var r struct {
		ErrCode *int   `json:"errcode"` // 企业微信 / 钉钉
		ErrMsg  string `json:"errmsg"`
		Code    *int   `json:"code"` // 飞书
		Msg     string `json:"msg"`
	}
	if json.Unmarshal(respBody, &r) == nil {
		if r.ErrCode != nil && *r.ErrCode != 0 {
			return fmt.Errorf("errcode %d: %s", *r.ErrCode, r.ErrMsg)
		}
		if r.Code != nil && *r.Code != 0 {
			return fmt.Errorf("code %d: %s", *r.Code, r.Msg)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Run 定期把新告警推送到所有启用的渠道。推送进度保存在数据库中，多个管理中心实例同时运行时
// 通过比较并交换只有一个实例处理同一批告警；先占位再发送，即同一告警最多推送一次。
// Run 定期推送新告警。active 为 false 时跳过（多实例部署时只由主实例推送；
// 即使多个实例同时推送，推送游标的比较并交换也保证每条告警只推送一次）。
func Run(ctx context.Context, st *store.Store, interval time.Duration, active func() bool) {
	hc := &http.Client{Timeout: 10 * time.Second}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !active() {
			continue
		}
		if err := RunOnce(ctx, st, hc); err != nil {
			slog.Warn("alert notification", "err", err)
		}
	}
}

func RunOnce(ctx context.Context, st *store.Store, hc *http.Client) error {
	// 领取（租约 30 秒）→ 推送 → 标记已推送：实例在推送途中宕机时，租约过期后由其他实例重新领取推送
	alerts, err := st.ClaimPendingAlerts(ctx, 500, 30*time.Second)
	if err != nil || len(alerts) == 0 {
		return err
	}
	ids := make([]int64, len(alerts))
	for i, a := range alerts {
		ids[i] = a.ID
	}
	defer func() {
		if err := st.MarkNotified(context.WithoutCancel(ctx), ids); err != nil {
			slog.Warn("mark alerts notified", "err", err)
		}
	}()
	channels, err := st.ListChannels(ctx)
	if err != nil {
		return err
	}
	// 攻击模拟自检产生的告警只用于验证，不推送
	real := alerts[:0:0]
	for _, a := range alerts {
		if a.Resolution != model.ResolutionSimulation {
			real = append(real, a)
		}
	}
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		matched := Filter(real, ch.MinSeverity)
		if len(matched) == 0 {
			continue
		}
		err := Send(ctx, hc, ch, matched)
		if err != nil {
			time.Sleep(2 * time.Second) // 网络抖动时重试一次
			err = Send(ctx, hc, ch, matched)
		}
		if err != nil {
			slog.Warn("notification failed", "channel", ch.Name, "alerts", len(matched), "err", err)
		}
		_ = st.RecordChannelResult(ctx, ch.ID, err)
	}
	return nil
}
