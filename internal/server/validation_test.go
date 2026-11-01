package server

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/vuln"
)

func TestSecurityValidation(t *testing.T) {
	ts, admin := newTestServer(t)
	call(t, ts, admin, "POST", "/api/v1/users", createUserRequest{Username: "second", Password: "second-password", Role: model.RoleAdmin}, nil)
	second := login(t, ts, "second", "second-password")

	run := func(tok string, weak bool, targets ...string) (int, model.ValidationRun) {
		t.Helper()
		var out model.ValidationRun
		code := call(t, ts, tok, "POST", "/api/v1/validation/runs", createValidationRequest{Name: "check", ProbeID: "seg-a", Targets: targets, WeakPassword: weak}, &out)
		return code, out
	}
	tasks := func() []model.ScanTask {
		t.Helper()
		var out []model.ScanTask
		call(t, ts, admin, "GET", "/api/v1/tasks", nil, &out)
		return out
	}

	// 没有授权范围：什么都不能验证，也不下发任务
	if code, _ := run(admin, false, "10.1.0.5"); code != http.StatusForbidden {
		t.Fatalf("no scope: %d", code)
	}
	for _, c := range []string{"0.0.0.0/0", "10.0.0.0/7", "not-an-ip"} {
		if code := call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": c, "note": "x"}, nil); code != http.StatusBadRequest {
			t.Errorf("scope %s: %d", c, code)
		}
	}
	if code := call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": "10.1.0.0/24"}, nil); code != http.StatusBadRequest {
		t.Errorf("scope without note: %d", code)
	}
	var scope model.ValidationScope
	if code := call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": "10.1.0.9/24", "note": "测试网段"}, &scope); code != http.StatusCreated || scope.CIDR != "10.1.0.0/24" {
		t.Fatalf("add scope: %d %+v", code, scope)
	}
	if code := call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": "10.1.0.0/24", "note": "again"}, nil); code != http.StatusConflict {
		t.Errorf("duplicate scope: %d", code)
	}

	// 范围外：只要有一个地址在范围外就拒绝，范围边界也算
	for _, target := range []string{"10.1.1.5", "10.1.0.250-260", "10.1.0.0/23"} {
		if code, _ := run(admin, false, "10.1.0.5", target); code != http.StatusForbidden && code != http.StatusBadRequest {
			t.Errorf("target %s: %d", target, code)
		}
	}
	if n := len(tasks()); n != 0 {
		t.Fatalf("rejected runs created %d tasks", n)
	}

	// 低风险：直接开始，下发的是漏洞检测任务
	code, low := run(admin, false, "10.1.0.5")
	if code != http.StatusCreated || low.Status != model.ValRunning {
		t.Fatalf("low risk: %d %+v", code, low)
	}
	got := tasks()
	if len(got) != 1 || got[0].Kind != model.TaskVuln || got[0].WeakPassword {
		t.Fatalf("task: %+v", got)
	}

	// 弱口令：不直接下发；发起人不能自己批准；另一位批准后才下发
	code, weak := run(admin, true, "10.1.0.6")
	if code != http.StatusCreated || weak.Status != model.ValAwaitingApproval || len(tasks()) != 1 {
		t.Fatalf("weak password: %d %+v", code, weak)
	}
	approve := "/api/v1/validation/runs/" + weak.ID + "/approve"
	if code := call(t, ts, admin, "POST", approve, nil, nil); code != http.StatusForbidden || len(tasks()) != 1 {
		t.Fatalf("self approval: %d", code)
	}
	if code := call(t, ts, second, "POST", approve, nil, nil); code != http.StatusNoContent {
		t.Fatalf("approve: %d", code)
	}
	got = tasks()
	if len(got) != 2 {
		t.Fatalf("tasks after approval: %d", len(got))
	}
	if code := call(t, ts, second, "POST", approve, nil, nil); code != http.StatusConflict || len(tasks()) != 2 {
		t.Errorf("approved twice: %d", code)
	}

	// 申请之后范围被删除：批准时重新检查
	_, pending := run(second, true, "10.1.0.7")
	if code := call(t, ts, admin, "DELETE", "/api/v1/validation/scopes/1", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete scope: %d", code)
	}
	if code := call(t, ts, admin, "POST", "/api/v1/validation/runs/"+pending.ID+"/approve", nil, nil); code != http.StatusForbidden || len(tasks()) != 2 {
		t.Errorf("approved after scope removed: %d", code)
	}

	// 扫描任务不能绕过审批发起弱口令检测
	if code := call(t, ts, admin, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.1.0.5"}, Kind: model.TaskVuln, WeakPassword: true}, nil); code != http.StatusBadRequest {
		t.Errorf("weak password through scan task: %d", code)
	}
}

func TestValidationReport(t *testing.T) {
	ts, admin := newTestServer(t)
	call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": "10.1.0.0/24", "note": "测试"}, nil)
	type report struct {
		Run      model.ValidationRun `json:"run"`
		Counts   map[string]int      `json:"counts"`
		Findings []model.Vuln        `json:"findings"`
		Fixed    []model.Vuln        `json:"fixed"`
	}
	start := func(targets ...string) report {
		t.Helper()
		var run model.ValidationRun
		call(t, ts, admin, "POST", "/api/v1/validation/runs", createValidationRequest{Name: "r", ProbeID: "seg-a", Targets: targets}, &run)
		var rep report
		call(t, ts, admin, "GET", "/api/v1/validation/runs/"+run.ID+"/report", nil, &rep)
		return rep
	}
	finish := func(rep report, checks ...model.CheckResult) report {
		t.Helper()
		call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, nil)
		if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", model.ScanReport{TaskID: rep.Run.TaskID, ProbeID: "seg-a",
			Assets: []model.Asset{}, Checks: checks, StartedAt: time.Now(), FinishedAt: time.Now()}, nil); code != http.StatusNoContent {
			t.Fatalf("probe report: %d", code)
		}
		var out report
		call(t, ts, admin, "GET", "/api/v1/validation/runs/"+rep.Run.ID+"/report", nil, &out)
		return out
	}
	redis := func(ip string, vulnerable bool) model.CheckResult {
		return model.CheckResult{IP: ip, Port: 6379, CheckID: "redis-unauth", Vulnerable: vulnerable, Title: "Redis 未授权访问", Severity: model.SeverityHigh, Detail: "无需密码"}
	}

	first := start("10.1.0.5")
	if first.Run.Status != model.ValRunning || first.Run.StartedAt == nil {
		t.Fatalf("not started: %+v", first.Run)
	}
	// 同一份结果里的其他主机不属于这次验证
	got := finish(first, redis("10.1.0.5", true), redis("10.1.0.6", true))
	if got.Run.Status != model.ValDone || len(got.Findings) != 1 || got.Findings[0].IP != "10.1.0.5" || got.Counts["high"] != 1 {
		t.Fatalf("first report: %+v", got)
	}
	// 修复后复查：问题进入“已修复”
	got = finish(start("10.1.0.5"), redis("10.1.0.5", false))
	if len(got.Findings) != 0 || len(got.Fixed) != 1 {
		t.Fatalf("recheck: %+v", got)
	}
}

func TestCoverageOf(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	rules := []alert.Rule{
		{ID: "a", Name: "a", Tactic: "执行 / 持久化", Simulation: "pass"},
		{ID: "b", Name: "b", Tactic: "执行", Simulation: "fail"},
		{ID: "c", Name: "c", Tactic: "发现", Simulation: "old"},
		{ID: "d", Name: "d", Tactic: "发现", Simulation: "na"},
		{ID: "e", Name: "e", Tactic: "发现"},
	}
	sims := []model.Simulation{ // 按时间倒序
		{Scenario: "pass", Status: model.SimPassed, LatencyMs: 3000, FinishedAt: ago(time.Hour)},
		{Scenario: "pass", Status: model.SimFailed, FinishedAt: ago(2 * time.Hour)},
		{Scenario: "fail", Status: model.SimFailed, FinishedAt: ago(time.Hour)},
		{Scenario: "fail", Status: model.SimPassed, LatencyMs: 1000, FinishedAt: ago(2 * time.Hour)},
		{Scenario: "old", Status: model.SimPassed, LatencyMs: 9000, FinishedAt: ago(31 * 24 * time.Hour)},
		{Scenario: "na", Status: model.SimNotApplicable, FinishedAt: ago(time.Hour)},
	}
	got := coverageOf(rules, sims, now)
	states := map[model.AlertType]string{}
	for _, c := range got["rules"].([]ruleCoverage) {
		states[c.ID] = c.State
	}
	want := map[model.AlertType]string{"a": "verified", "b": "failed", "c": "not_run", "d": "not_run", "e": "no_scenario"}
	if !reflect.DeepEqual(states, want) {
		t.Errorf("states: %v", states)
	}
	if got["avg_latency_ms"] != int64(2000) {
		t.Errorf("latency: %v", got["avg_latency_ms"])
	}
	counts := map[string]int{}
	for _, x := range got["tactics"].([]map[string]any) {
		counts[x["tactic"].(string)] = x["rules"].(int)
	}
	if counts["执行"] != 2 || counts["持久化"] != 1 || counts["影响"] != 0 {
		t.Errorf("tactics: %v", counts)
	}
}

// Nuclei 和弱口令一样需要批准；任务带上 nuclei 标记；完整运行后没有再出现的发现视为已修复，失败的运行不算。
func TestValidationNuclei(t *testing.T) {
	ts, admin := newTestServer(t)
	call(t, ts, admin, "POST", "/api/v1/users", createUserRequest{Username: "second", Password: "second-password", Role: model.RoleAdmin}, nil)
	second := login(t, ts, "second", "second-password")
	call(t, ts, admin, "POST", "/api/v1/validation/scopes", map[string]string{"cidr": "10.1.0.0/24", "note": "测试"}, nil)
	finding := model.CheckResult{IP: "10.1.0.5", Port: 80, CheckID: vuln.NucleiPrefix + "demo", Vulnerable: true, Title: "demo", Severity: model.SeverityHigh}
	scan := func(errMsg string, checks ...model.CheckResult) {
		t.Helper()
		var run model.ValidationRun
		call(t, ts, admin, "POST", "/api/v1/validation/runs", createValidationRequest{Name: "n", ProbeID: "seg-a", Targets: []string{"10.1.0.5"}, Nuclei: true}, &run)
		if run.Status != model.ValAwaitingApproval {
			t.Fatalf("nuclei run not awaiting approval: %+v", run)
		}
		if code := call(t, ts, second, "POST", "/api/v1/validation/runs/"+run.ID+"/approve", nil, nil); code != http.StatusNoContent {
			t.Fatalf("approve: %d", code)
		}
		var tasks []model.ScanTask
		call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, &tasks)
		if len(tasks) != 1 || !tasks[0].Nuclei {
			t.Fatalf("claimed: %+v", tasks)
		}
		rep := model.ScanReport{TaskID: tasks[0].ID, ProbeID: "seg-a", Assets: []model.Asset{{IP: "10.1.0.5", Ports: []model.Port{{Port: 80, Proto: "tcp"}}}},
			Checks: checks, Error: errMsg, StartedAt: time.Now(), FinishedAt: time.Now()}
		if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", rep, nil); code != http.StatusNoContent {
			t.Fatalf("report: %d", code)
		}
	}
	status := func() model.VulnStatus {
		t.Helper()
		var out []model.Vuln
		call(t, ts, admin, "GET", "/api/v1/vulns", nil, &out)
		for _, v := range out {
			if v.CheckID == finding.CheckID {
				return v.Status
			}
		}
		return ""
	}
	scan("", finding)
	if s := status(); s != model.VulnOpen {
		t.Fatalf("after finding: %q", s)
	}
	scan("nuclei: exit status 1")
	if s := status(); s != model.VulnOpen {
		t.Errorf("failed run closed a finding: %q", s)
	}
	scan("")
	if s := status(); s != model.VulnFixed {
		t.Errorf("not fixed after clean run: %q", s)
	}
}
