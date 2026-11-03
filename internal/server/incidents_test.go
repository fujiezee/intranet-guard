package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/netintel"
)

// 网络侧事件（主机上没有 Agent）的详情中 agents 必须是 []：控制台按数组读取，null 会让详情抽屉渲染失败。
func TestIncidentDetailWithoutAgent(t *testing.T) {
	ts, adminToken := newTestServer(t)
	call(t, ts, probeToken, "POST", "/api/v1/probe/net-findings", netFindingReport{ProbeID: "seg-a", Findings: []netintel.Finding{
		{Kind: "beacon", Severity: "medium", SrcIP: "10.0.0.111", Peer: "203.0.113.50:443", Time: time.Now(), Detail: "周期性连接"}}}, nil)
	var list []model.Incident
	call(t, ts, adminToken, "GET", "/api/v1/incidents", nil, &list)
	if len(list) != 1 || list[0].IP != "10.0.0.111" {
		t.Fatalf("network-only incident: %+v", list)
	}
	var raw map[string]json.RawMessage
	call(t, ts, adminToken, "GET", fmt.Sprintf("/api/v1/incidents/%d", list[0].ID), nil, &raw)
	for _, k := range []string{"agents", "alerts", "events", "notes"} {
		if v := string(raw[k]); !strings.HasPrefix(v, "[") {
			t.Errorf("%s = %s, want a JSON array", k, v)
		}
	}
}

func TestIncidentsAndRisk(t *testing.T) {
	ts, adminToken := newTestServer(t)
	// 资产 10.0.0.21：开放 22 和高危的 6379
	runTask(t, ts, adminToken, true, []int{22, 6379}, asset("10.0.0.21", 22, 6379))

	report := func(id, ip string, events ...model.HostEvent) {
		t.Helper()
		if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{
			Agent: model.AgentInfo{ID: id, Hostname: id, IPs: []string{ip}}, Events: events}, nil); code != http.StatusOK {
			t.Fatalf("report: %d", code)
		}
	}
	incidents := func(status string) []model.Incident {
		t.Helper()
		var list []model.Incident
		call(t, ts, adminToken, "GET", "/api/v1/incidents?status="+status, nil, &list)
		return list
	}
	now := time.Now()

	// 1. 爆破（凭据获取）→ 开启事件
	var fails []model.HostEvent
	for i := 0; i < 10; i++ {
		fails = append(fails, model.HostEvent{Type: model.EventLoginFailed, Time: now, User: "root", SrcIP: "10.9.9.9"})
	}
	report("web01", "10.0.0.21", fails...)
	list := incidents("open")
	if len(list) != 1 || list[0].IP != "10.0.0.21" || strings.Join(list[0].Stages, ",") != "credential" {
		t.Fatalf("after brute force: %+v", list)
	}

	// 2. 登录成功（初始访问）+ 交互命令 + 反弹 shell（执行）→ 并入同一事件，3 个阶段升级为高危
	report("web01", "10.0.0.21",
		model.HostEvent{Type: model.EventLoginSuccess, Time: now, User: "root", SrcIP: "10.9.9.9", Detail: "ssh password"},
		model.HostEvent{Type: model.EventCommand, Time: now, User: "root", Detail: "id（父进程 bash）"},
		model.HostEvent{Type: model.EventSuspiciousCommand, Time: now, User: "root", SrcIP: "10.9.9.9", Severity: "medium",
			Detail: "[下载并执行] 命令匹配特征；命令：curl x | sh；父进程：bash"})
	list = incidents("")
	if len(list) != 1 {
		t.Fatalf("alerts not merged into one incident: %+v", list)
	}
	in := list[0]
	if strings.Join(in.Stages, ",") != "credential,initial,execution" || in.Severity != model.SeverityHigh || in.AlertCount < 4 {
		t.Errorf("merged incident: %+v", in)
	}

	// 3. 详情：告警 + 该主机期间的审计记录（登录、命令）
	var d incidentDetail
	call(t, ts, adminToken, "GET", fmt.Sprintf("/api/v1/incidents/%d", in.ID), nil, &d)
	types := map[model.HostEventType]bool{}
	for _, e := range d.Events {
		types[e.Type] = true
	}
	if len(d.Alerts) != in.AlertCount || !types[model.EventCommand] || !types[model.EventLoginSuccess] || len(d.Agents) != 1 {
		t.Errorf("detail: alerts=%d events=%v agents=%v", len(d.Alerts), types, d.Agents)
	}

	// 4. 不形成事件的情况：资产变化告警、Agent 离线（只能并入已有事件）、自检告警
	runTask(t, ts, adminToken, false, []int{22}, asset("10.0.0.77", 22))
	report("db01", "10.0.0.31", model.HostEvent{}) // 先上报，再停止
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{
		Agent: model.AgentInfo{ID: "db01", IPs: []string{"10.0.0.31"}, Stopping: true}, Events: []model.HostEvent{}}, nil)
	if n := len(incidents("")); n != 1 {
		t.Errorf("non-intrusion alerts opened incidents: %d", n)
	}

	// 5. 风险分：未结高危事件 + 高危端口 6379；设为核心资产后加权
	var a model.Asset
	call(t, ts, adminToken, "GET", "/api/v1/assets/10.0.0.21", nil, &a)
	base := a.Risk
	if base < riskTestMin || !strings.Contains(strings.Join(a.RiskReasons, " "), "6379") {
		t.Errorf("risk = %d %v", a.Risk, a.RiskReasons)
	}
	if code := call(t, ts, adminToken, "PUT", "/api/v1/assets/10.0.0.21/meta",
		map[string]any{"importance": "core", "owner": "张工", "tags": []string{"数据库", "生产"}}, nil); code != http.StatusNoContent {
		t.Fatalf("set meta: %d", code)
	}
	call(t, ts, adminToken, "GET", "/api/v1/assets/10.0.0.21", nil, &a)
	if a.Importance != "core" || a.Owner != "张工" || len(a.Tags) != 2 || (a.Risk <= base && a.Risk != 100) {
		t.Errorf("after meta: %+v", a)
	}

	// 6. 处置记录、结案：事件下未处理的告警一并确认；之后的新告警开启新事件
	if code := call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/incidents/%d/notes", in.ID),
		map[string]string{"body": "已隔离主机，排查 curl 下载的样本"}, nil); code != http.StatusCreated {
		t.Errorf("note: %d", code)
	}
	assignee := "张工"
	if code := call(t, ts, adminToken, "PATCH", fmt.Sprintf("/api/v1/incidents/%d", in.ID),
		map[string]any{"status": "resolved", "assignee": assignee}, nil); code != http.StatusNoContent {
		t.Fatalf("resolve: %d", code)
	}
	call(t, ts, adminToken, "GET", fmt.Sprintf("/api/v1/incidents/%d", in.ID), nil, &d)
	for _, al := range d.Alerts {
		if al.Status != model.AlertAcked {
			t.Errorf("alert left open after resolve: %+v", al)
		}
	}
	if d.Incident.Assignee != "张工" || len(d.Notes) != 1 {
		t.Errorf("resolved incident: %+v notes=%d", d.Incident, len(d.Notes))
	}
	report("web01", "10.0.0.21", model.HostEvent{Type: model.EventWebshell, Time: now, Path: "/var/www/x.php", Detail: "新增脚本文件", Severity: "medium"})
	if open := incidents("open"); len(open) != 1 || open[0].ID == in.ID || open[0].Stages[0] != "persistence" {
		t.Errorf("new incident after resolve: %+v", open)
	}

	var st struct {
		OpenIncidents map[string]int `json:"open_incidents"`
	}
	call(t, ts, adminToken, "GET", "/api/v1/stats", nil, &st)
	if st.OpenIncidents["medium"] != 1 {
		t.Errorf("stats open incidents: %v", st.OpenIncidents)
	}
}

const riskTestMin = 40 + 10 // 高危事件 + 高危端口
