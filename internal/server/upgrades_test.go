package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/store"
)

func TestAgentUpgrades(t *testing.T) {
	_, adminToken, st := newTestServerWithStore(t)
	dist := t.TempDir()
	os.WriteFile(filepath.Join(dist, "manifest.json"), []byte(`{"version": "0.9.0"}`), 0o644)
	os.WriteFile(filepath.Join(dist, "safe-agent-linux-amd64"), []byte("AGENT-0.9.0"), 0o755)
	srv := New(Config{ProbeToken: probeToken, AgentToken: agentToken, DistDir: dist}, st)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	nodes := httptest.NewServer(srv) // 测试中节点用共享令牌认证，节点接口与控制台在同一处理器上
	defer nodes.Close()

	report := func(id, ver, osArch string, results ...model.CommandResult) []model.AgentCommand {
		t.Helper()
		var resp model.AgentReportResponse
		rep := model.AgentReport{Agent: model.AgentInfo{ID: id, Hostname: id, OS: osArch, Version: ver, IPs: []string{"10.0.0.1"}},
			Events: []model.HostEvent{}, Results: results}
		if code := call(t, nodes, agentToken, "POST", "/api/v1/agent/report", rep, &resp); code != http.StatusOK {
			t.Fatalf("report: %d", code)
		}
		var ups []model.AgentCommand
		for _, c := range resp.Commands {
			if c.Type == "upgrade" {
				ups = append(ups, c)
			}
		}
		return ups
	}
	state := func(id string) store.AgentUpgrade {
		t.Helper()
		var out struct {
			Latest struct{ Version string }
			Policy store.UpgradePolicy
			Agents []upgradeAgent
		}
		call(t, ts, adminToken, "GET", "/api/v1/upgrades", nil, &out)
		for _, a := range out.Agents {
			if a.ID == id && a.Upgrade != nil {
				return *a.Upgrade
			}
		}
		return store.AgentUpgrade{}
	}
	policy := func(p store.UpgradePolicy) {
		t.Helper()
		if code := call(t, ts, adminToken, "PUT", "/api/v1/upgrades/policy", p, nil); code != http.StatusNoContent {
			t.Fatalf("set policy: %d", code)
		}
	}

	// 最常见的情况：已是最新版本、从未升级过（曾因"查无记录"被当成错误，导致上报失败）
	if ups := report("new01", "0.9.0", "linux/amd64"); len(ups) != 0 {
		t.Fatalf("up-to-date agent got an upgrade: %+v", ups)
	}
	if a, _, err := st.NextUpgrade(context.Background(), "never-upgraded", "0.9.0", "0.9.0", store.DefaultUpgradePolicy()); err != nil || a != "" {
		t.Fatalf("NextUpgrade for an up-to-date agent without history: %q %v", a, err)
	}

	// 默认手动：旧版本 Agent 上报不会收到升级
	if ups := report("web01", "0.8.0", "linux/amd64"); len(ups) != 0 {
		t.Fatalf("manual mode sent upgrade without request: %+v", ups)
	}
	// 管理员选择升级 → 下次上报收到指令（带版本、文件名、SHA-256）
	call(t, ts, adminToken, "POST", "/api/v1/upgrades", map[string]any{"agent_ids": []string{"web01"}}, nil)
	ups := report("web01", "0.8.0", "linux/amd64")
	if len(ups) != 1 || ups[0].Params["version"] != "0.9.0" || ups[0].Params["file"] != "safe-agent-linux-amd64" || len(ups[0].Params["sha256"]) != 64 {
		t.Fatalf("upgrade command: %+v", ups)
	}
	if s := state("web01"); s.State != store.UpgradeRunning {
		t.Errorf("state after dispatch: %+v", s)
	}
	if len(report("web01", "0.8.0", "linux/amd64")) != 0 {
		t.Error("upgrade sent twice")
	}
	// 以新版本上报 → 成功
	report("web01", "0.9.0", "linux/amd64")
	if s := state("web01"); s.State != store.UpgradeSucceeded {
		t.Errorf("after new version report: %+v", s)
	}

	// 失败：Agent 回报错误（自检失败 / 已回退）
	call(t, ts, adminToken, "POST", "/api/v1/upgrades", map[string]any{"agent_ids": []string{"web02"}}, nil)
	ups = report("web02", "0.8.0", "linux/amd64")
	report("web02", "0.8.0", "linux/amd64", model.CommandResult{ID: ups[0].ID, Status: "error", Detail: "新版本自检失败"})
	if s := state("web02"); s.State != store.UpgradeFailed || s.Detail != "新版本自检失败" {
		t.Errorf("failed upgrade: %+v", s)
	}
	// 没有该平台的程序
	call(t, ts, adminToken, "POST", "/api/v1/upgrades", map[string]any{"agent_ids": []string{"arm01"}}, nil)
	if len(report("arm01", "0.8.0", "linux/arm64")) != 0 {
		t.Error("upgrade sent without a binary for the platform")
	}
	if s := state("arm01"); s.State != store.UpgradeFailed {
		t.Errorf("missing platform: %+v", s)
	}

	// 自动：分批（每批 1 台），失败达到 2 台时暂停
	policy(store.UpgradePolicy{Mode: "auto", MaxConcurrent: 1, MaxFailures: 3})
	if ups := report("dev01", "dev", "linux/amd64"); len(ups) != 0 {
		t.Error("development build auto-upgraded")
	}
	if ups := report("web02", "0.8.0", "linux/amd64"); len(ups) != 0 {
		t.Error("auto mode retried a version that already failed on this host")
	}
	a1 := report("app01", "0.8.0", "linux/amd64")
	if len(a1) != 1 {
		t.Fatalf("auto upgrade not started")
	}
	if len(report("app02", "0.8.0", "linux/amd64")) != 0 {
		t.Error("batch limit exceeded")
	}
	report("app01", "0.8.0", "linux/amd64", model.CommandResult{ID: a1[0].ID, Status: "error", Detail: "已自动回退"})
	// web02、arm01、app01 共 3 台失败 → 暂停
	var out struct{ Policy store.UpgradePolicy }
	call(t, ts, adminToken, "GET", "/api/v1/upgrades", nil, &out)
	if !out.Policy.Paused || out.Policy.PausedReason == "" {
		t.Fatalf("not paused after failures: %+v", out.Policy)
	}
	srv.invalidatePolicy()
	if len(report("app02", "0.8.0", "linux/amd64")) != 0 {
		t.Error("upgrade sent while paused")
	}
	// 恢复后继续
	policy(store.UpgradePolicy{Mode: "auto", MaxConcurrent: 1, MaxFailures: 10})
	if len(report("app02", "0.8.0", "linux/amd64")) != 1 {
		t.Error("auto upgrade did not resume")
	}

	// 超时：下发后 10 分钟没有以新版本上报
	if n, err := st.ExpireUpgrades(context.Background(), time.Now().Add(11*time.Minute)); err != nil || n != 1 {
		t.Errorf("expire: %d %v", n, err)
	}
	if s := state("app02"); s.State != store.UpgradeFailed {
		t.Errorf("timed out upgrade: %+v", s)
	}

	// 只读用户不能发起升级或修改策略
	call(t, ts, adminToken, "POST", "/api/v1/users", createUserRequest{Username: "ro", Password: "readonly-password", Role: model.RoleViewer}, nil)
	ro := login(t, ts, "ro", "readonly-password")
	if code := call(t, ts, ro, "POST", "/api/v1/upgrades", map[string]any{"agent_ids": []string{"web01"}}, nil); code != http.StatusForbidden {
		t.Errorf("viewer queue: %d", code)
	}
}
