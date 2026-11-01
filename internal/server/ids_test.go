package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"safe/internal/model"
)

func TestIDS(t *testing.T) {
	ts, adminToken := newTestServer(t)

	// 让 10.1.0.8 成为已知资产，IDS 告警应关联到它。
	runTask(t, ts, adminToken, true, []int{445}, asset("10.1.0.8", 445))

	ev := func(sid int64, sev int, src, dst string) model.IDSEvent {
		return model.IDSEvent{Time: time.Now(), SrcIP: src, SrcPort: 50000, DestIP: dst, DestPort: 445, Proto: "TCP",
			SignatureID: sid, Signature: fmt.Sprintf("rule %d", sid), Category: "test", Severity: sev}
	}
	send := func(events ...model.IDSEvent) {
		t.Helper()
		if code := call(t, ts, probeToken, "POST", "/api/v1/probe/ids-events", model.IDSReport{ProbeID: "seg-a", Events: events}, nil); code != http.StatusNoContent {
			t.Fatalf("submit: %d", code)
		}
	}
	idsAlerts := func() []model.Alert {
		t.Helper()
		var all, out []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &all)
		for _, a := range all {
			if a.Type == model.AlertIDS {
				out = append(out, a)
			}
		}
		return out
	}

	send(
		ev(1001, 1, "203.0.113.5", "10.1.0.8"), // 高
		ev(1001, 1, "203.0.113.5", "10.1.0.8"), // 重复，去重
		ev(1002, 2, "10.1.0.99", "10.1.0.50"),  // 中，均不在资产库，关联内网目的地址
		ev(1003, 3, "10.1.0.99", "10.1.0.8"),   // 低优先级只记录
	)
	alerts := idsAlerts()
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v", alerts)
	}
	byIP := map[string]model.Alert{}
	for _, a := range alerts {
		byIP[a.IP] = a
	}
	if a := byIP["10.1.0.8"]; a.Severity != model.SeverityHigh || a.Port != 445 {
		t.Errorf("alert for asset = %+v", a)
	}
	if a := byIP["10.1.0.50"]; a.Severity != model.SeverityMedium {
		t.Errorf("alert for unknown internal host = %+v", a)
	}

	// 抑制规则 2001 的所有来源、规则 2002 的特定来源。
	var sp model.IDSSuppression
	if code := call(t, ts, adminToken, "POST", "/api/v1/ids/suppressions", model.IDSSuppression{SignatureID: 2001}, &sp); code != http.StatusCreated {
		t.Fatalf("create suppression: %d", code)
	}
	call(t, ts, adminToken, "POST", "/api/v1/ids/suppressions", model.IDSSuppression{SignatureID: 2002, SrcIP: "10.1.0.200"}, nil)
	if code := call(t, ts, adminToken, "POST", "/api/v1/ids/suppressions", model.IDSSuppression{SignatureID: 2001}, nil); code != http.StatusConflict {
		t.Errorf("duplicate suppression: %d", code)
	}
	send(ev(2001, 1, "10.1.0.5", "10.1.0.8"), ev(2002, 1, "10.1.0.200", "10.1.0.8"), ev(2002, 1, "10.1.0.201", "10.1.0.8"))
	if n := len(idsAlerts()); n != 3 {
		t.Fatalf("after suppression: %d alerts, want 3 (only 2002 from .201 is new)", n)
	}

	var events []model.IDSEvent
	call(t, ts, adminToken, "GET", "/api/v1/ids/events?signature_id=2002", nil, &events)
	suppressed := 0
	for _, e := range events {
		if e.Suppressed {
			suppressed++
		}
	}
	if len(events) != 2 || suppressed != 1 {
		t.Errorf("events for 2002 = %+v", events)
	}
	call(t, ts, adminToken, "GET", "/api/v1/ids/events?max_severity=2", nil, &events)
	for _, e := range events {
		if e.Severity > 2 {
			t.Errorf("max_severity filter returned %+v", e)
		}
	}

	// 删除抑制后恢复告警。
	if code := call(t, ts, adminToken, "DELETE", fmt.Sprintf("/api/v1/ids/suppressions/%d", sp.ID), nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete suppression: %d", code)
	}
	send(ev(2001, 1, "10.1.0.5", "10.1.0.8"))
	if n := len(idsAlerts()); n != 4 {
		t.Errorf("after removing suppression: %d alerts, want 4", n)
	}

	viewer := func() string {
		call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "v", Password: "viewer-password", Role: model.RoleViewer}, nil)
		return login(t, ts, "v", "viewer-password")
	}()
	if code := call(t, ts, viewer, "POST", "/api/v1/ids/suppressions", model.IDSSuppression{SignatureID: 9}, nil); code != http.StatusForbidden {
		t.Errorf("viewer create suppression: %d", code)
	}
}
