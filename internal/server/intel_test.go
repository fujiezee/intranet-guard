package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/netintel"
)

func TestThreatIntel(t *testing.T) {
	ts, adminToken := newTestServer(t)
	alertsOf := func(typ model.AlertType) []model.Alert {
		var all, out []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &all)
		for _, a := range all {
			if a.Type == typ {
				out = append(out, a)
			}
		}
		return out
	}
	probeCfg := func() probeConfigResponse {
		var pc probeConfigResponse
		call(t, ts, probeToken, "POST", "/api/v1/probe/config?probe_id=seg-a", probeConfigRequest{}, &pc)
		return pc
	}
	probeIntelList := func() map[string]netintel.Indicator {
		var pi probeIntel
		call(t, ts, probeToken, "GET", "/api/v1/probe/intel?probe_id=seg-a", nil, &pi)
		m := map[string]netintel.Indicator{}
		for _, i := range pi.Indicators {
			m[i.Value] = i
		}
		return m
	}

	// 1. 手工导入；内置自检域名始终下发；版本号递增
	v0 := probeCfg().IntelVersion
	var res map[string]int
	if code := call(t, ts, adminToken, "POST", "/api/v1/intel/indicators",
		map[string]any{"text": "203.0.113.9\nevil.com\n10.0.0.1\n", "severity": "high", "note": "演练通报"}, &res); code != http.StatusOK ||
		res["parsed"] != 2 || res["added"] != 2 {
		t.Fatalf("add: %d %v", code, res)
	}
	if v1 := probeCfg().IntelVersion; v1 <= v0 {
		t.Errorf("version not bumped: %d -> %d", v0, v1)
	}
	list := probeIntelList()
	if list["evil.com"].Source != "自定义" || list["safe-sim.example.com"].Value == "" || len(list) != 3 {
		t.Errorf("probe intel: %+v", list)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/intel/indicators", map[string]any{"text": "nothing here", "severity": "high"}, nil); code != http.StatusBadRequest {
		t.Errorf("empty import: %d", code)
	}

	// 2. 订阅源：hosts 文件格式；停用后不下发；删除后条目一并删除
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "# hostfile\n127.0.0.1\tmalware.example\n127.0.0.1\tphish.example\n")
	}))
	defer feed.Close()
	var f model.IntelFeed
	if code := call(t, ts, adminToken, "POST", "/api/v1/intel/feeds",
		model.IntelFeed{Name: "URLhaus", URL: feed.URL, Severity: model.SeverityMedium}, &f); code != http.StatusCreated {
		t.Fatalf("create feed: %d", code)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/intel/feeds", model.IntelFeed{Name: "x", URL: "file:///etc/passwd", Severity: "high"}, nil); code != http.StatusBadRequest {
		t.Errorf("non-http feed accepted: %d", code)
	}
	call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/intel/feeds/%d/refresh", f.ID), nil, &f)
	if f.Count != 2 || f.LastError != "" || f.LastFetch == nil {
		t.Fatalf("refresh: %+v", f)
	}
	if _, ok := probeIntelList()["malware.example"]; ok {
		t.Error("disabled feed delivered to probes")
	}
	call(t, ts, adminToken, "PATCH", fmt.Sprintf("/api/v1/intel/feeds/%d", f.ID), map[string]bool{"enabled": true}, nil)
	if got := probeIntelList()["malware.example"]; got.Source != "URLhaus" || got.Severity != "medium" {
		t.Errorf("enabled feed: %+v", got)
	}
	feed.Close() // 拉取失败时保留旧条目并记录错误
	call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/intel/feeds/%d/refresh", f.ID), nil, &f)
	if f.Count != 2 || f.LastError == "" {
		t.Errorf("failed refresh: %+v", f)
	}
	call(t, ts, adminToken, "DELETE", fmt.Sprintf("/api/v1/intel/feeds/%d", f.ID), nil, nil)
	if _, ok := probeIntelList()["malware.example"]; ok {
		t.Error("indicators of deleted feed still delivered")
	}

	// 3. 探针分析结果 → 告警，关联内网主机，归入“命令控制”阶段
	findings := []netintel.Finding{
		{Kind: "intel", Severity: "high", SrcIP: "10.0.0.5", Peer: "cdn.evil.com", Time: time.Now(), Detail: "10.0.0.5 查询了情报中的域名 cdn.evil.com（情报来源：自定义）"},
		{Kind: "beacon", Severity: "medium", SrcIP: "10.0.0.5", Peer: "203.0.113.50:443", Time: time.Now(), Detail: "10.0.0.5 每隔约 1m0s 连接一次 203.0.113.50:443"},
		{Kind: "dns_tunnel", Severity: "high", SrcIP: "10.0.0.6", Peer: "t.example", Time: time.Now(), Detail: "疑似 DNS 隧道"},
		{Kind: "exfil", Severity: "medium", SrcIP: "10.0.0.7", Peer: "203.0.113.20", Time: time.Now(), Detail: "疑似数据外传"},
	}
	for i := 0; i < 2; i++ { // 重复上报去重
		if code := call(t, ts, probeToken, "POST", "/api/v1/probe/net-findings", netFindingReport{ProbeID: "seg-a", Findings: findings}, nil); code != http.StatusNoContent {
			t.Fatalf("net findings: %d", code)
		}
	}
	if a := alertsOf(model.AlertThreatIntel); len(a) != 1 || a[0].IP != "10.0.0.5" || !strings.Contains(a[0].Message, "探针 seg-a") {
		t.Errorf("intel alert: %+v", a)
	}
	if len(alertsOf(model.AlertBeacon)) != 1 || len(alertsOf(model.AlertDNSAnomaly)) != 1 || len(alertsOf(model.AlertExfil)) != 1 {
		t.Error("network finding alerts missing")
	}
	var incidents []model.Incident
	call(t, ts, adminToken, "GET", "/api/v1/incidents", nil, &incidents)
	stages := map[string]string{}
	for _, in := range incidents {
		stages[in.IP] = strings.Join(in.Stages, ",")
	}
	if stages["10.0.0.5"] != "c2" || stages["10.0.0.7"] != "exfil" {
		t.Errorf("incident stages: %v", stages)
	}

	// 4. 管理中心侧匹配：情报地址登录主机、IDS 告警的对端在情报中
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: model.AgentInfo{ID: "web01", IPs: []string{"10.0.0.21"}},
		Events: []model.HostEvent{{Type: model.EventLoginSuccess, Time: time.Now(), User: "root", SrcIP: "203.0.113.9"}}}, nil)
	call(t, ts, probeToken, "POST", "/api/v1/probe/ids-events", model.IDSReport{ProbeID: "seg-a", Events: []model.IDSEvent{
		{Time: time.Now(), SrcIP: "10.0.0.30", DestIP: "203.0.113.9", DestPort: 443, Proto: "TCP", SignatureID: 1, Signature: "ET MALWARE test", Severity: 1}}}, nil)
	var login, ids bool
	for _, a := range alertsOf(model.AlertThreatIntel) {
		login = login || (a.IP == "10.0.0.21" && strings.Contains(a.Message, "203.0.113.9 登录成功") && a.Severity == model.SeverityHigh)
		ids = ids || (a.IP == "10.0.0.30" && strings.Contains(a.Message, "ET MALWARE test"))
	}
	if !login || !ids {
		t.Errorf("server-side intel match: login=%v ids=%v %+v", login, ids, alertsOf(model.AlertThreatIntel))
	}

	// 5. 情报自检：探针上报带自检编号的命中 → 自检通过，告警不进入未处理
	var sims []model.Simulation
	call(t, ts, adminToken, "POST", "/api/v1/simulations", createSimulationsRequest{AgentID: "web01", Scenarios: []string{"intel_dns"}}, &sims)
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: model.AgentInfo{ID: "web01", IPs: []string{"10.0.0.21"}}, Events: []model.HostEvent{}}, nil)
	qname := sims[0].ID + ".safe-sim.example.com"
	call(t, ts, probeToken, "POST", "/api/v1/probe/net-findings", netFindingReport{ProbeID: "seg-a", Findings: []netintel.Finding{
		{Kind: "intel", Severity: "high", SrcIP: "10.0.0.21", Peer: qname, Time: time.Now(), Detail: "10.0.0.21 查询了情报中的域名 " + qname}}}, nil)
	call(t, ts, adminToken, "GET", "/api/v1/simulations", nil, &sims)
	if sims[0].Status != model.SimPassed {
		t.Errorf("intel simulation: %+v", sims[0])
	}

	// 6. 分析参数
	if code := call(t, ts, adminToken, "PUT", "/api/v1/intel/net-config", netintel.Config{WorkStart: 9, WorkEnd: 8}, nil); code != http.StatusBadRequest {
		t.Errorf("invalid work hours accepted: %d", code)
	}
	call(t, ts, adminToken, "PUT", "/api/v1/intel/net-config", netintel.Config{WorkStart: 8, WorkEnd: 20, ExfilBytes: 2 << 30, Allow: []string{"*.Backup.Example"}}, nil)
	if pc := probeCfg(); pc.Net.WorkStart != 8 || pc.Net.ExfilBytes != 2<<30 || len(pc.Net.Allow) != 1 || pc.Net.Allow[0] != "backup.example" {
		t.Errorf("net config: %+v", pc.Net)
	}
}
