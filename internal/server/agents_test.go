package server

import (
	"context"
	"net/http"
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
