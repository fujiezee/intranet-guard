package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/store"
)

// vulnScan 创建漏洞检测任务并以给定资产和检查结果上报。
func vulnScan(t *testing.T, ts *httptest.Server, adminToken string, assets []model.Asset, checks ...model.CheckResult) {
	t.Helper()
	var task model.ScanTask
	if code := call(t, ts, adminToken, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.5"},
		Ports: []int{22, 6379}, Kind: model.TaskVuln, WeakPassword: true}, &task); code != http.StatusCreated {
		t.Fatalf("create vuln task: %d", code)
	}
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, nil)
	if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", model.ScanReport{TaskID: task.ID, ProbeID: "seg-a",
		Assets: assets, Checks: checks, StartedAt: time.Now(), FinishedAt: time.Now()}, nil); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
}

func TestVulnLifecycle(t *testing.T) {
	ts, adminToken := newTestServer(t)
	host := func(ports ...int) []model.Asset {
		a := model.Asset{IP: "10.0.0.5", Ports: []model.Port{}}
		for _, p := range ports {
			port := model.Port{Port: p, Proto: "tcp"}
			if p == 22 {
				port.Banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
			}
			a.Ports = append(a.Ports, port)
		}
		return []model.Asset{a}
	}
	redis := func(vulnerable bool) model.CheckResult {
		r := model.CheckResult{IP: "10.0.0.5", Port: 6379, CheckID: "redis-unauth", Vulnerable: vulnerable}
		if vulnerable {
			r.Title, r.Severity, r.Detail = "Redis 未授权访问", model.SeverityHigh, "无需密码"
		}
		return r
	}
	vulns := func(status string) map[string]model.Vuln {
		t.Helper()
		var list []model.Vuln
		call(t, ts, adminToken, "GET", "/api/v1/vulns?status="+status, nil, &list)
		out := map[string]model.Vuln{}
		for _, v := range list {
			out[v.CheckID] = v
		}
		return out
	}
	vulnAlerts := func() []string {
		t.Helper()
		var alerts []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
		var out []string
		for _, a := range alerts {
			if a.Type == model.AlertVuln {
				out = append(out, a.Message)
			}
		}
		return out
	}

	// 1. 首次发现：Redis 未授权 + Banner 匹配到 regreSSHion。
	vulnScan(t, ts, adminToken, host(22, 6379), redis(true))
	open := vulns("open")
	if len(open) != 2 || open["redis-unauth"].Severity != model.SeverityHigh || open["CVE-2024-6387"].Port != 22 {
		t.Fatalf("open vulns = %+v", open)
	}
	if n := len(vulnAlerts()); n != 2 {
		t.Fatalf("vuln alerts = %d, want 2", n)
	}

	// 2. 复查：Redis 已加密码 → 已修复；SSH 仍存在且不重复告警。
	vulnScan(t, ts, adminToken, host(22, 6379), redis(false))
	if v := vulns("fixed")["redis-unauth"]; v.FixedAt == nil {
		t.Errorf("redis not marked fixed: %+v", v)
	}
	if len(vulnAlerts()) != 2 {
		t.Errorf("repeat finding raised a new alert")
	}

	// 3. 忽略 SSH 漏洞（例如已确认发行版回移植了补丁）；再次发现也保持忽略、不告警。
	ssh := vulns("open")["CVE-2024-6387"]
	if code := call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/vulns/%d/status", ssh.ID),
		map[string]string{"status": "ignored"}, nil); code != http.StatusNoContent {
		t.Fatalf("ignore: %d", code)
	}
	vulnScan(t, ts, adminToken, host(22, 6379))
	if _, ok := vulns("ignored")["CVE-2024-6387"]; !ok || len(vulnAlerts()) != 2 {
		t.Errorf("ignored vuln changed state or alerted")
	}

	// 4. Redis 问题复发 → 重新打开并告警"漏洞复发"。
	vulnScan(t, ts, adminToken, host(22, 6379), redis(true))
	alerts := vulnAlerts()
	if v := vulns("open")["redis-unauth"]; v.Status != model.VulnOpen || v.FixedAt != nil || len(alerts) != 3 ||
		!strings.HasPrefix(alerts[0], "漏洞复发") {
		t.Errorf("reopen: %+v alerts=%v", v, alerts)
	}

	// 5. Redis 端口关闭 → 该端口漏洞随之修复。
	vulnScan(t, ts, adminToken, host(22))
	if _, ok := vulns("fixed")["redis-unauth"]; !ok {
		t.Errorf("vuln on closed port not fixed")
	}

	var st store.Stats
	call(t, ts, adminToken, "GET", "/api/v1/stats", nil, &st)
	if len(st.OpenVulns) != 0 {
		t.Errorf("open vulns in stats = %v (ssh is ignored, redis fixed)", st.OpenVulns)
	}

	// 校验：弱口令检测只能用于漏洞检测任务；只读用户不能修改漏洞状态。
	if code := call(t, ts, adminToken, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.5"},
		WeakPassword: true}, nil); code != http.StatusBadRequest {
		t.Errorf("weak_password on discovery task: %d", code)
	}
	call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "v", Password: "viewer-password", Role: model.RoleViewer}, nil)
	viewer := login(t, ts, "v", "viewer-password")
	if code := call(t, ts, viewer, "POST", fmt.Sprintf("/api/v1/vulns/%d/status", ssh.ID),
		map[string]string{"status": "open"}, nil); code != http.StatusForbidden {
		t.Errorf("viewer change status: %d", code)
	}
}
