package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
)

func TestAuditLog(t *testing.T) {
	ts, adminToken := newTestServer(t)
	call(t, ts, "", "POST", "/api/v1/auth/login", loginRequest{"admin", "wrong-password"}, nil)
	call(t, ts, adminToken, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.0/24"}}, nil)
	call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "bob", Password: "bob-password-1", Role: model.RoleViewer}, nil)

	var entries []model.AuditEntry
	call(t, ts, adminToken, "GET", "/api/v1/audit", nil, &entries)
	got := map[string]model.AuditEntry{}
	for _, e := range entries {
		key := e.Action
		if !e.Success {
			key += ":fail"
		}
		got[key] = e
	}
	for _, want := range []string{"auth.login", "auth.login:fail", "task.create", "user.create"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing audit %q in %v", want, entries)
		}
	}
	if e := got["task.create"]; e.Username != "admin" || !strings.Contains(e.Detail, "10.0.0.0/24") || e.ClientIP == "" {
		t.Errorf("task.create entry = %+v", e)
	}

	bob := login(t, ts, "bob", "bob-password-1")
	if code := call(t, ts, bob, "GET", "/api/v1/audit", nil, nil); code != http.StatusForbidden {
		t.Errorf("viewer reading audit: %d", code)
	}
}

func TestNotifyChannels(t *testing.T) {
	ts, adminToken := newTestServer(t)
	var received int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		w.Write([]byte(`{"errcode":0}`))
	}))
	defer hook.Close()

	secretURL := hook.URL + "/robot/send?access_token=0123456789abcdef0123"
	var ch model.NotifyChannel
	if code := call(t, ts, adminToken, "POST", "/api/v1/notify-channels", model.NotifyChannel{Name: "安全组", Type: model.ChannelDingTalk,
		URL: secretURL, Secret: "SECxyz", MinSeverity: model.SeverityMedium}, &ch); code != http.StatusCreated {
		t.Fatalf("create channel: %d", code)
	}
	var list []model.NotifyChannel
	call(t, ts, adminToken, "GET", "/api/v1/notify-channels", nil, &list)
	if len(list) != 1 || strings.Contains(list[0].URL, "0123456789abcdef") || !strings.HasSuffix(list[0].URL, "****0123") ||
		list[0].Secret != "" || !list[0].Enabled {
		t.Errorf("listed channel leaks secrets or wrong: %+v", list[0])
	}

	if code := call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/notify-channels/%d/test", ch.ID), nil, nil); code != http.StatusNoContent || received != 1 {
		t.Errorf("test send: %d, received %d", code, received)
	}
	for _, bad := range []model.NotifyChannel{
		{Name: "x", Type: "email", URL: "https://a.b", MinSeverity: model.SeverityLow},
		{Name: "x", Type: model.ChannelWebhook, URL: "file:///etc/passwd", MinSeverity: model.SeverityLow},
		{Name: "x", Type: model.ChannelWebhook, URL: "https://a.b", MinSeverity: "critical"},
	} {
		if code := call(t, ts, adminToken, "POST", "/api/v1/notify-channels", bad, nil); code != http.StatusBadRequest {
			t.Errorf("invalid channel %+v accepted: %d", bad, code)
		}
	}
	if code := call(t, ts, adminToken, "DELETE", fmt.Sprintf("/api/v1/notify-channels/%d", ch.ID), nil, nil); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
}

func TestStaleTasks(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	var task model.ScanTask
	call(t, ts, adminToken, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.1"}}, &task)
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, nil)

	if ids, _ := st.FailStaleTasks(context.Background(), time.Now().Add(-time.Hour)); len(ids) != 0 {
		t.Fatalf("fresh task failed: %v", ids)
	}
	ids, err := st.FailStaleTasks(context.Background(), time.Now().Add(time.Second))
	if err != nil || len(ids) != 1 || ids[0] != task.ID {
		t.Fatalf("FailStaleTasks = %v, %v", ids, err)
	}
	var got model.ScanTask
	call(t, ts, adminToken, "GET", "/api/v1/tasks/"+task.ID, nil, &got)
	if got.Status != model.TaskFailed || got.Error == "" {
		t.Errorf("task = %+v", got)
	}
	// 迟到的结果仍然接收。
	if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", model.ScanReport{TaskID: task.ID, ProbeID: "seg-a",
		Assets: []model.Asset{asset("10.0.0.1", 22)}, FinishedAt: time.Now()}, nil); code != http.StatusNoContent {
		t.Errorf("late report: %d", code)
	}
	call(t, ts, adminToken, "GET", "/api/v1/tasks/"+task.ID, nil, &got)
	if got.Status != model.TaskDone {
		t.Errorf("late report did not complete task: %+v", got)
	}
}
