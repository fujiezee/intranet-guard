package server

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"safe/internal/model"
	"safe/internal/store"
)

// audit 记录一次管理操作。username 为空时取当前登录用户。审计写入失败只记日志，不影响操作本身。
func (s *Server) audit(r *http.Request, username, action, target, detail string, success bool) {
	if username == "" {
		username = userFrom(r.Context()).Username
	}
	e := model.AuditEntry{Time: time.Now(), Username: username, Action: action, Target: target, Detail: detail,
		ClientIP: s.clientIP(r), Success: success}
	slog.Info("audit", "user", e.Username, "action", action, "target", target, "detail", detail, "ip", e.ClientIP, "success", success)
	// 用独立 context：请求结束（例如客户端断开）也要写完审计记录。
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.store.AddAudit(ctx, e); err != nil {
		slog.Error("write audit log", "err", err)
	}
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Username: q.Get("username"), Action: q.Get("action"), Limit: 500}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "limit must be within 1-5000")
			return
		}
		f.Limit = n
	}
	entries, err := s.store.ListAudit(r.Context(), f)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
