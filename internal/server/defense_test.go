package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/notify"
)

func TestHoneypotAndSimulation(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	ctx := context.Background()

	// 推送渠道：记录推送内容，用来确认自检告警不推送。
	var mu sync.Mutex
	var pushed []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		pushed = append(pushed, string(b))
		mu.Unlock()
	}))
	defer hook.Close()
	st.CreateChannel(ctx, model.NotifyChannel{Name: "all", Type: model.ChannelWebhook, URL: hook.URL, MinSeverity: model.SeverityLow, Enabled: true})
	notify.RunOnce(ctx, st, http.DefaultClient) // 初始化推送游标

	// 1. 为探针 seg-a 启用蜜罐，探针拉取配置并上报地址与监听状态。
	cfg := model.HoneypotConfig{Enabled: true, Services: []model.HoneypotService{{Type: "ssh", Port: 2222}, {Type: "redis", Port: 6379}}}
	if code := call(t, ts, adminToken, "PUT", "/api/v1/honeypots/seg-a", cfg, nil); code != http.StatusNoContent {
		t.Fatalf("set honeypot: %d", code)
	}
	if code := call(t, ts, adminToken, "PUT", "/api/v1/honeypots/seg-a", model.HoneypotConfig{Enabled: true,
		Services: []model.HoneypotService{{Type: "ssh", Port: 22}, {Type: "ssh", Port: 22}}}, nil); code != http.StatusBadRequest {
		t.Errorf("duplicate port accepted: %d", code)
	}
	var pc probeConfigResponse
	call(t, ts, probeToken, "POST", "/api/v1/probe/config?probe_id=seg-a",
		probeConfigRequest{IPs: []string{"10.0.0.9"}, Status: map[int]string{2222: "listening", 6379: "address already in use"}}, &pc)
	if !pc.Honeypot.Enabled || len(pc.Honeypot.Services) != 2 {
		t.Fatalf("probe config: %+v", pc)
	}

	// 2. 真实访问：告警关联到来源主机，同来源同服务去重。
	attack := model.HoneypotEvent{Time: time.Now(), Service: "ssh", Port: 2222, SrcIP: "10.0.0.66", SrcPort: 50000,
		Username: "root", Password: "1*****", Detail: "SSH 密码登录尝试"}
	for i := 0; i < 2; i++ {
		if code := call(t, ts, probeToken, "POST", "/api/v1/probe/honeypot-events",
			honeypotReport{ProbeID: "seg-a", Events: []model.HoneypotEvent{attack}}, nil); code != http.StatusNoContent {
			t.Fatalf("honeypot events: %d", code)
		}
	}
	honeypotAlerts := func() []model.Alert {
		var all, out []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &all)
		for _, a := range all {
			if a.Type == model.AlertHoneypot {
				out = append(out, a)
			}
		}
		return out
	}
	if a := honeypotAlerts(); len(a) != 1 || a[0].IP != "10.0.0.66" || a[0].Severity != model.SeverityHigh ||
		!strings.Contains(a[0].Message, "尝试用户 root 密码 1*****") {
		t.Fatalf("honeypot alerts: %+v", a)
	}

	// 3. 蜜罐地址上的伪装端口不产生资产告警，资产中标识为蜜罐。
	runTask(t, ts, adminToken, false, []int{2222, 6379}, asset("10.0.0.9", 2222, 6379))
	var alerts []model.Alert
	call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
	for _, a := range alerts {
		if a.IP == "10.0.0.9" {
			t.Errorf("asset alert for honeypot IP: %+v", a)
		}
	}
	var hp model.Asset
	call(t, ts, adminToken, "GET", "/api/v1/assets/10.0.0.9", nil, &hp)
	if !hp.Honeypot {
		t.Errorf("honeypot asset not flagged")
	}

	// 蜜罐没有运行时，含蜜罐场景的请求整体拒绝，不会只创建一部分。
	call(t, ts, adminToken, "PUT", "/api/v1/honeypots/seg-a", model.HoneypotConfig{Enabled: false, Services: cfg.Services}, nil)
	if code := call(t, ts, adminToken, "POST", "/api/v1/simulations",
		createSimulationsRequest{AgentID: "web01", Scenarios: []string{"fim", "honeypot"}}, nil); code != http.StatusBadRequest {
		t.Errorf("simulation without honeypot: %d", code)
	}
	var none []model.Simulation
	call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &none)
	if len(none) != 0 {
		t.Errorf("partial simulations created: %+v", none)
	}
	call(t, ts, adminToken, "PUT", "/api/v1/honeypots/seg-a", cfg, nil)

	// 4. 下发三个自检场景，Agent 上报时领取。
	var sims []model.Simulation
	if code := call(t, ts, adminToken, "POST", "/api/v1/simulations",
		createSimulationsRequest{AgentID: "web01", Scenarios: []string{"fim", "process", "honeypot"}}, &sims); code != http.StatusCreated || len(sims) != 3 {
		t.Fatalf("create simulations: %d %+v", code, sims)
	}
	id := map[string]string{}
	for _, s := range sims {
		id[s.Scenario] = s.ID
	}
	agentInfo := model.AgentInfo{ID: "web01", Hostname: "web01", IPs: []string{"10.0.0.20"}}
	var resp model.AgentReportResponse
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: []model.HostEvent{}}, &resp)
	if len(resp.Commands) != 3 {
		t.Fatalf("commands: %+v", resp.Commands)
	}
	for _, c := range resp.Commands {
		if c.Scenario == "honeypot" && c.Params["target"] != "10.0.0.9:2222" {
			t.Errorf("honeypot target = %q (6379 is not listening, so 2222 must be chosen)", c.Params["target"])
		}
	}
	// 再次上报不会重复下发。
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: []model.HostEvent{}}, &resp)
	if len(resp.Commands) != 0 {
		t.Errorf("commands delivered twice: %+v", resp.Commands)
	}

	// 5. Agent 回报：process 不适用；文件篡改被真实检测链路发现 → 通过。
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo,
		Results: []model.CommandResult{{ID: id["process"], Status: "not_applicable", Detail: "进程检测仅支持 Linux"}},
		Events: []model.HostEvent{{Type: model.EventFileChanged, Time: time.Now(),
			Path: "/etc/cron.d/safe-simulation-" + id["fim"], Detail: "created"}}}, nil)
	// 蜜罐收到带自检标记的连接 → 通过。
	call(t, ts, probeToken, "POST", "/api/v1/probe/honeypot-events", honeypotReport{ProbeID: "seg-a", Events: []model.HoneypotEvent{
		{Time: time.Now(), Service: "ssh", Port: 2222, SrcIP: "10.0.0.20", Detail: "攻击模拟自检 " + id["honeypot"], SimulationID: id["honeypot"]}}}, nil)

	var list []model.Simulation
	call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &list)
	status := map[string]model.Simulation{}
	for _, s := range list {
		status[s.Scenario] = s
	}
	if s := status["fim"]; s.Status != model.SimPassed || s.AlertID == 0 {
		t.Errorf("fim: %+v", s)
	}
	if s := status["honeypot"]; s.Status != model.SimPassed {
		t.Errorf("honeypot: %+v", s)
	}
	if s := status["process"]; s.Status != model.SimNotApplicable || s.Detail == "" {
		t.Errorf("process: %+v", s)
	}

	// 自检产生的告警已关闭、标记为自检，不计入未处理。
	call(t, ts, adminToken, "GET", "/api/v1/alerts?status=open", nil, &alerts)
	for _, a := range alerts {
		if strings.Contains(a.Message, "sim-") {
			t.Errorf("simulation alert left open: %+v", a)
		}
	}

	// 6. 推送：真实的蜜罐告警推送了，自检告警没有。
	notify.RunOnce(ctx, st, http.DefaultClient)
	mu.Lock()
	all := strings.Join(pushed, "\n")
	mu.Unlock()
	if !strings.Contains(all, "10.0.0.66") || strings.Contains(all, "sim-") {
		t.Errorf("pushed = %s", all)
	}

	// 7. 检测失效：超时未出现告警 → 失败。
	call(t, ts, adminToken, "POST", "/api/v1/simulations", createSimulationsRequest{AgentID: "web01", Scenarios: []string{"fim"}}, &sims)
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: []model.HostEvent{}}, &resp)
	if n, err := st.ExpireSimulations(ctx, time.Now().Add(10*time.Minute)); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &list)
	if list[0].ID != sims[0].ID || list[0].Status != model.SimFailed {
		t.Errorf("expired simulation: %+v", list[0])
	}

	// 登录类自检：只有预期的告警类型才算通过；重复执行不被去重挡住。
	loginEvents := func(id string, kind model.HostEventType, n int) []model.HostEvent {
		ev := model.HostEvent{Type: kind, Time: time.Now(), User: "safe-sim", SrcIP: "192.0.2.7", Detail: "ssh password", SimulationID: id}
		out := make([]model.HostEvent, n)
		for i := range out {
			out[i] = ev
		}
		return out
	}
	for round := 0; round < 2; round++ {
		call(t, ts, adminToken, "POST", "/api/v1/simulations", createSimulationsRequest{AgentID: "web01", Scenarios: []string{"brute_force_login"}}, &sims)
		call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: []model.HostEvent{}}, &resp)
		call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: loginEvents(sims[0].ID, model.EventLoginFailed, 10)}, nil)
		call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &list)
		if list[0].ID != sims[0].ID || list[0].Status != model.SimRunning {
			t.Errorf("round %d: passed on the brute force alert alone: %+v", round, list[0])
		}
		call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: agentInfo, Events: loginEvents(sims[0].ID, model.EventLoginSuccess, 1)}, nil)
		call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &list)
		if list[0].Status != model.SimPassed {
			t.Errorf("round %d: %+v", round, list[0])
		}
	}
	call(t, ts, adminToken, "GET", "/api/v1/alerts?status=open", nil, &alerts)
	for _, a := range alerts {
		if strings.Contains(a.Message, "sim-") {
			t.Errorf("simulation alert left open: %+v", a)
		}
	}

	// 8. 误报标记：必须填原因。
	real := honeypotAlerts()[0]
	if code := call(t, ts, adminToken, "POST", "/api/v1/alerts/"+itoa(real.ID)+"/ack",
		map[string]any{"false_positive": true}, nil); code != http.StatusBadRequest {
		t.Errorf("false positive without reason: %d", code)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/alerts/"+itoa(real.ID)+"/ack",
		map[string]any{"false_positive": true, "reason": "授权的漏洞扫描器"}, nil); code != http.StatusNoContent {
		t.Fatalf("mark false positive: %d", code)
	}
	if a := honeypotAlerts()[0]; a.Resolution != model.ResolutionFalsePositive || a.ResolutionNote != "授权的漏洞扫描器" {
		t.Errorf("false positive not recorded: %+v", a)
	}

	// 9. 规则目录：每条有 ATT&CK 信息，蜜罐规则关联自检场景。
	var rules struct {
		Rules []alert.Rule `json:"rules"`
	}
	call(t, ts, adminToken, "GET", "/api/v1/rules", nil, &rules)
	found := false
	for _, r := range rules.Rules {
		if r.ID == model.AlertHoneypot && r.Simulation == "honeypot" {
			found = true
		}
	}
	if !found || len(rules.Rules) < 10 {
		t.Errorf("rules: %d entries", len(rules.Rules))
	}
}

// 每种告警类型都必须在规则目录中登记。
func TestCatalogCoversAllAlertTypes(t *testing.T) {
	types := []model.AlertType{model.AlertNewAsset, model.AlertNewPort, model.AlertRiskyPort, model.AlertSSHBruteForce,
		model.AlertBruteForceSuccess, model.AlertRootLogin, model.AlertFileChanged, model.AlertSuspiciousProcess,
		model.AlertAgentOffline, model.AlertIDS, model.AlertVuln, model.AlertHoneypot,
		model.AlertSuspiciousCommand, model.AlertWebshell, model.AlertLateralMovement, model.AlertAgentStopped,
		model.AlertAccountChange, model.AlertDomainAttack, model.AlertThreatIntel, model.AlertDNSAnomaly, model.AlertBeacon, model.AlertExfil}
	have := map[model.AlertType]bool{}
	for _, r := range alert.Catalog {
		have[r.ID] = true
	}
	for _, typ := range types {
		if !have[typ] {
			t.Errorf("alert type %s missing from catalog", typ)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
