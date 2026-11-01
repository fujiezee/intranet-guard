package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/store/storetest"
)

type captured struct {
	mu    sync.Mutex
	reqs  []*http.Request
	body  []map[string]any
	reply string
}

func (c *captured) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		c.mu.Lock()
		c.reqs, c.body = append(c.reqs, r), append(c.body, m)
		c.mu.Unlock()
		reply := c.reply
		if reply == "" {
			reply = `{"errcode":0,"errmsg":"ok"}`
		}
		w.Write([]byte(reply))
	}))
	t.Cleanup(s.Close)
	return s
}

func alerts() []model.Alert {
	now := time.Now()
	return []model.Alert{
		{ID: 1, Severity: model.SeverityHigh, Message: "SSH 爆破", CreatedAt: now},
		{ID: 2, Severity: model.SeverityLow, Message: "新端口", CreatedAt: now},
	}
}

func TestFormats(t *testing.T) {
	ctx := context.Background()
	hc := http.DefaultClient

	var wecom captured
	s := wecom.server(t)
	if err := Send(ctx, hc, model.NotifyChannel{Type: model.ChannelWeCom, URL: s.URL}, alerts()); err != nil {
		t.Fatal(err)
	}
	content := wecom.body[0]["markdown"].(map[string]any)["content"].(string)
	if wecom.body[0]["msgtype"] != "markdown" || !strings.Contains(content, "[高] SSH 爆破") || !strings.Contains(content, "高危 1") {
		t.Errorf("wecom payload = %v", wecom.body[0])
	}

	// 钉钉加签：timestamp + sign 放在 URL 上，签名可用密钥验证。
	var ding captured
	s = ding.server(t)
	if err := Send(ctx, hc, model.NotifyChannel{Type: model.ChannelDingTalk, URL: s.URL + "/robot/send?access_token=x", Secret: "SEC123"}, alerts()); err != nil {
		t.Fatal(err)
	}
	q := ding.reqs[0].URL.Query()
	mac := hmac.New(sha256.New, []byte("SEC123"))
	mac.Write([]byte(q.Get("timestamp") + "\nSEC123"))
	if q.Get("access_token") != "x" || q.Get("sign") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Errorf("dingtalk signature wrong: %v", q)
	}

	// 飞书加签：签名在消息体里。
	var feishu captured
	feishu.reply = `{"code":0,"msg":"success"}`
	s = feishu.server(t)
	if err := Send(ctx, hc, model.NotifyChannel{Type: model.ChannelFeishu, URL: s.URL, Secret: "FS"}, alerts()); err != nil {
		t.Fatal(err)
	}
	b := feishu.body[0]
	mac = hmac.New(sha256.New, []byte(b["timestamp"].(string)+"\nFS"))
	if b["msg_type"] != "text" || b["sign"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Errorf("feishu payload = %v", b)
	}

	// 机器人返回业务错误码（如签名错误、关键词不匹配）时视为失败。
	var bad captured
	bad.reply = `{"errcode":310000,"errmsg":"sign not match"}`
	s = bad.server(t)
	if err := Send(ctx, hc, model.NotifyChannel{Type: model.ChannelDingTalk, URL: s.URL}, alerts()); err == nil ||
		!strings.Contains(err.Error(), "sign not match") {
		t.Errorf("business error not reported: %v", err)
	}
}

func TestTruncation(t *testing.T) {
	var many []model.Alert
	for i := 0; i < 100; i++ {
		many = append(many, model.Alert{Severity: model.SeverityMedium, Message: strings.Repeat("长消息", 20)})
	}
	_, text := format(many)
	if len(text) > 4096 || !strings.Contains(text, "另有") {
		t.Errorf("len=%d, tail=%q", len(text), text[len(text)-60:])
	}
}

// 多个实例同时运行时，每条告警只推送一次；渠道按级别过滤；首次运行不推送历史告警。
func TestRunOnce(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)

	st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "p", Events: []model.IDSEvent{
		{Time: time.Now(), SrcIP: "1.1.1.1", DestIP: "10.0.0.1", SignatureID: 1, Signature: "old", Severity: 1}}})
	var hook captured
	s := hook.server(t)
	st.CreateChannel(ctx, model.NotifyChannel{Name: "all", Type: model.ChannelWebhook, URL: s.URL, MinSeverity: model.SeverityLow, Enabled: true})
	st.CreateChannel(ctx, model.NotifyChannel{Name: "high", Type: model.ChannelWebhook, URL: s.URL + "/high", MinSeverity: model.SeverityHigh, Enabled: true})
	st.CreateChannel(ctx, model.NotifyChannel{Name: "off", Type: model.ChannelWebhook, URL: s.URL + "/off", MinSeverity: model.SeverityLow, Enabled: false})

	RunOnce(ctx, st, http.DefaultClient) // 初始化游标：历史告警不推送
	if len(hook.reqs) != 0 {
		t.Fatalf("historical alerts pushed")
	}

	st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "p", Events: []model.IDSEvent{
		{Time: time.Now(), SrcIP: "2.2.2.2", DestIP: "10.0.0.1", SignatureID: 2, Signature: "exploit", Severity: 1},
		{Time: time.Now(), SrcIP: "3.3.3.3", DestIP: "10.0.0.1", SignatureID: 3, Signature: "scan", Severity: 2},
	}})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); RunOnce(ctx, st, http.DefaultClient) }()
	}
	wg.Wait()

	paths := map[string]int{}
	for i, r := range hook.reqs {
		paths[r.URL.Path] += len(hook.body[i]["alerts"].([]any))
	}
	if paths["/"] != 2 || paths["/high"] != 1 || paths["/off"] != 0 || len(hook.reqs) != 2 {
		t.Errorf("deliveries = %v (requests %d)", paths, len(hook.reqs))
	}
	chans, _ := st.ListChannels(ctx)
	if chans[0].LastSentAt == nil || chans[0].LastError != "" {
		t.Errorf("channel result not recorded: %+v", chans[0])
	}
}
