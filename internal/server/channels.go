package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/notify"
	"safe/internal/store"
)

// maskURL 隐藏 Webhook 地址中的令牌：查询参数只保留末 4 位，路径中的长段（如飞书的 hook ID）同样处理。
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "****"
	}
	mask := func(v string) string {
		if len(v) <= 8 {
			return "****"
		}
		return "****" + v[len(v)-4:]
	}
	q := u.Query()
	for k, vs := range q {
		for i := range vs {
			vs[i] = mask(vs[i])
		}
		q[k] = vs
	}
	u.RawQuery = q.Encode()
	parts := strings.Split(u.Path, "/")
	for i, p := range parts {
		if len(p) >= 16 {
			parts[i] = mask(p)
		}
	}
	u.Path = strings.Join(parts, "/")
	s, _ := url.PathUnescape(u.String())
	return s
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	chans, err := s.store.ListChannels(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	for i := range chans {
		chans[i].URL = maskURL(chans[i].URL)
		chans[i].Secret = ""
	}
	writeJSON(w, http.StatusOK, chans)
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	var c model.NotifyChannel
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	c.Name = strings.TrimSpace(c.Name)
	switch {
	case c.Name == "" || len(c.Name) > 64:
		writeError(w, http.StatusBadRequest, "name must be 1-64 characters")
		return
	case c.Type != model.ChannelWeCom && c.Type != model.ChannelDingTalk && c.Type != model.ChannelFeishu && c.Type != model.ChannelWebhook:
		writeError(w, http.StatusBadRequest, "type must be wecom, dingtalk, feishu or webhook")
		return
	case c.MinSeverity != model.SeverityLow && c.MinSeverity != model.SeverityMedium && c.MinSeverity != model.SeverityHigh:
		writeError(w, http.StatusBadRequest, "min_severity must be low, medium or high")
		return
	}
	if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		writeError(w, http.StatusBadRequest, "url must be an http(s) URL")
		return
	}
	c.Enabled = true
	c, err := s.store.CreateChannel(r.Context(), c)
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "notify_channel.create", c.Name, "type="+string(c.Type)+" min_severity="+string(c.MinSeverity), true)
	c.URL, c.Secret = maskURL(c.URL), ""
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) setChannelEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.SetChannelEnabled(r.Context(), id, req.Enabled); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "notify_channel.enabled", strconv.FormatInt(id, 10), "enabled="+strconv.FormatBool(req.Enabled), true)
	w.WriteHeader(http.StatusNoContent)
}

// testChannel 立即发送一条测试消息，返回发送结果，便于排查关键词 / 签名 / IP 白名单等配置问题。
func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ch, err := s.store.GetChannel(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	test := []model.Alert{{Severity: model.SeverityHigh, Type: "test", CreatedAt: time.Now(),
		Message: "这是一条测试告警，用于验证推送渠道配置（由 " + userFrom(r.Context()).Username + " 发送）"}}
	sendErr := notify.Send(r.Context(), &http.Client{Timeout: 10 * time.Second}, ch, test)
	_ = s.store.RecordChannelResult(r.Context(), id, sendErr)
	if sendErr != nil {
		writeError(w, http.StatusBadGateway, "send failed: "+sendErr.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteChannel(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "notify_channel.delete", strconv.FormatInt(id, 10), "", true)
	w.WriteHeader(http.StatusNoContent)
}
