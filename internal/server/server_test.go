package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/pki"
	"safe/internal/store"
	"safe/internal/store/storetest"
)

const (
	probeToken    = "probe-token-0123456789"
	agentToken    = "agent-token-0123456789"
	adminPassword = "admin-password-1"
)

// newTestServer 启动测试服务器，创建 admin 用户并返回其会话 token。
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	ts, tok, _ := newTestServerWithStore(t)
	return ts, tok
}

func newTestServerWithStore(t *testing.T) (*httptest.Server, string, *store.Store) {
	t.Helper()
	st := storetest.Open(t)
	hash, _ := HashPassword(adminPassword)
	if _, err := st.CreateUser(context.Background(), "admin", hash, model.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ca, _, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(Config{CA: ca, ProbeToken: probeToken, AgentToken: agentToken}, st))
	t.Cleanup(ts.Close)
	return ts, login(t, ts, "admin", adminPassword), st
}

func login(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	var resp loginResponse
	if code := call(t, ts, "", "POST", "/api/v1/auth/login", loginRequest{username, password}, &resp); code != http.StatusOK {
		t.Fatalf("login %s: %d", username, code)
	}
	return resp.Token
}

func call(t *testing.T, ts *httptest.Server, token, method, path string, body, out any) int {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, ts.URL+path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestScanWorkflow(t *testing.T) {
	ts, adminToken := newTestServer(t)

	var task model.ScanTask
	code := call(t, ts, adminToken, "POST", "/api/v1/tasks",
		createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.0/24"}, Ports: []int{22, 80}}, &task)
	if code != http.StatusCreated || task.Status != model.TaskPending {
		t.Fatalf("create task: %d %+v", code, task)
	}

	// 别的探针领不到这个任务。
	var other []model.ScanTask
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-b", nil, &other)
	if len(other) != 0 {
		t.Fatalf("seg-b claimed %d tasks", len(other))
	}

	var claimed []model.ScanTask
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, &claimed)
	if len(claimed) != 1 || claimed[0].ID != task.ID || claimed[0].Status != model.TaskRunning {
		t.Fatalf("claim: %+v", claimed)
	}
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, &claimed)
	if len(claimed) != 0 {
		t.Fatalf("task claimed twice")
	}

	report := func(taskID string, ports ...int) {
		t.Helper()
		a := model.Asset{IP: "10.0.0.5", Hostname: "db01"}
		for _, p := range ports {
			a.Ports = append(a.Ports, model.Port{Port: p, Proto: "tcp", Service: "x"})
		}
		code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", model.ScanReport{
			TaskID: taskID, ProbeID: "seg-a", Assets: []model.Asset{a},
			StartedAt: time.Now(), FinishedAt: time.Now(),
		}, nil)
		if code != http.StatusNoContent {
			t.Fatalf("report: %d", code)
		}
	}
	report(task.ID, 22, 80)

	var got model.ScanTask
	call(t, ts, adminToken, "GET", "/api/v1/tasks/"+task.ID, nil, &got)
	if got.Status != model.TaskDone {
		t.Fatalf("task status = %s", got.Status)
	}

	// 第二次只扫 80 且 80 已关闭：80 应被移除，没扫到的 22 保留。
	var task2 model.ScanTask
	call(t, ts, adminToken, "POST", "/api/v1/tasks",
		createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.5"}, Ports: []int{80}}, &task2)
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, &claimed)
	report(task2.ID)

	var asset model.Asset
	if code := call(t, ts, adminToken, "GET", "/api/v1/assets/10.0.0.5", nil, &asset); code != http.StatusOK {
		t.Fatalf("get asset: %d", code)
	}
	if asset.Hostname != "db01" || len(asset.Ports) != 1 || asset.Ports[0].Port != 22 {
		t.Fatalf("asset = %+v", asset)
	}
}

func TestAuthAndValidation(t *testing.T) {
	ts, adminToken := newTestServer(t)

	if code := call(t, ts, "", "GET", "/api/v1/assets", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code := call(t, ts, probeToken, "GET", "/api/v1/assets", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("probe token on admin API: %d", code)
	}
	if code := call(t, ts, adminToken, "GET", "/api/v1/probe/tasks?probe_id=x", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("admin token on probe API: %d", code)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/tasks",
		createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.0/8"}}, nil); code != http.StatusBadRequest {
		t.Errorf("oversized CIDR: %d", code)
	}
	if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports",
		model.ScanReport{TaskID: "nope", ProbeID: "seg-a"}, nil); code != http.StatusNotFound {
		t.Errorf("unknown task report: %d", code)
	}
}

// runTask 创建任务、由探针领取并上报给定资产。
func runTask(t *testing.T, ts *httptest.Server, adminToken string, baseline bool, ports []int, assets ...model.Asset) {
	t.Helper()
	var task model.ScanTask
	call(t, ts, adminToken, "POST", "/api/v1/tasks",
		createTaskRequest{ProbeID: "seg-a", Targets: []string{"10.0.0.0/24"}, Ports: ports, Baseline: baseline}, &task)
	call(t, ts, probeToken, "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, nil)
	if code := call(t, ts, probeToken, "POST", "/api/v1/probe/reports", model.ScanReport{
		TaskID: task.ID, ProbeID: "seg-a", Assets: assets, StartedAt: time.Now(), FinishedAt: time.Now(),
	}, nil); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
}

func asset(ip string, ports ...int) model.Asset {
	a := model.Asset{IP: ip, Ports: []model.Port{}}
	for _, p := range ports {
		a.Ports = append(a.Ports, model.Port{Port: p, Proto: "tcp"})
	}
	return a
}

func TestAlerts(t *testing.T) {
	ts, adminToken := newTestServer(t)
	ports := []int{22, 80, 6379}

	// 基线扫描不产生告警。
	runTask(t, ts, adminToken, true, ports, asset("10.0.0.1", 22))
	var alerts []model.Alert
	call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
	if len(alerts) != 0 {
		t.Fatalf("baseline produced alerts: %+v", alerts)
	}

	// 已知主机新开 redis + 新主机上线。
	runTask(t, ts, adminToken, false, ports, asset("10.0.0.1", 22, 6379), asset("10.0.0.2", 80))
	call(t, ts, adminToken, "GET", "/api/v1/alerts?status=open", nil, &alerts)
	got := map[string]bool{}
	for _, a := range alerts {
		got[fmt.Sprintf("%s %s %d", a.Type, a.IP, a.Port)] = true
	}
	want := []string{"risky_port 10.0.0.1 6379", "new_asset 10.0.0.2 0"}
	if len(alerts) != len(want) {
		t.Fatalf("alerts = %+v", alerts)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing alert %q in %v", w, got)
		}
	}

	// 状态不变的重复扫描不再告警。
	runTask(t, ts, adminToken, false, ports, asset("10.0.0.1", 22, 6379), asset("10.0.0.2", 80))
	call(t, ts, adminToken, "GET", "/api/v1/alerts", nil, &alerts)
	if len(alerts) != 2 {
		t.Fatalf("repeat scan produced alerts: %d", len(alerts))
	}

	if code := call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/alerts/%d/ack", alerts[0].ID), nil, nil); code != http.StatusNoContent {
		t.Fatalf("ack: %d", code)
	}
	call(t, ts, adminToken, "GET", "/api/v1/alerts?status=open", nil, &alerts)
	if len(alerts) != 1 {
		t.Fatalf("open alerts after ack = %d", len(alerts))
	}

	var st store.Stats
	call(t, ts, adminToken, "GET", "/api/v1/stats", nil, &st)
	if st.Assets != 2 || st.OpenPorts != 3 || st.OpenAlerts["high"]+st.OpenAlerts["medium"] != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestRBAC(t *testing.T) {
	ts, adminToken := newTestServer(t)

	var u model.User
	if code := call(t, ts, adminToken, "POST", "/api/v1/users",
		createUserRequest{Username: "alice", Password: "short", Role: model.RoleViewer}, nil); code != http.StatusBadRequest {
		t.Errorf("weak password: %d", code)
	}
	if code := call(t, ts, adminToken, "POST", "/api/v1/users",
		createUserRequest{Username: "alice", Password: "viewer-password", Role: model.RoleViewer}, &u); code != http.StatusCreated {
		t.Fatalf("create viewer: %d", code)
	}
	viewerToken := login(t, ts, "alice", "viewer-password")

	if code := call(t, ts, viewerToken, "GET", "/api/v1/assets", nil, nil); code != http.StatusOK {
		t.Errorf("viewer read assets: %d", code)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/tasks"},
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/alerts/1/ack"},
	} {
		if code := call(t, ts, viewerToken, c.method, c.path, nil, nil); code != http.StatusForbidden {
			t.Errorf("viewer %s %s: %d", c.method, c.path, code)
		}
	}

	// admin 是唯一管理员，不能删除自己；删除 alice 后其会话失效。
	if code := call(t, ts, adminToken, "DELETE", "/api/v1/users/1", nil, nil); code != http.StatusBadRequest {
		t.Errorf("delete self: %d", code)
	}
	if code := call(t, ts, adminToken, "DELETE", fmt.Sprintf("/api/v1/users/%d", u.ID), nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete alice: %d", code)
	}
	if code := call(t, ts, viewerToken, "GET", "/api/v1/assets", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("deleted user's session still valid: %d", code)
	}

	// 登出后 token 失效。
	call(t, ts, adminToken, "POST", "/api/v1/auth/logout", nil, nil)
	if code := call(t, ts, adminToken, "GET", "/api/v1/auth/me", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("token valid after logout: %d", code)
	}
}

func TestLoginLockout(t *testing.T) {
	ts, _ := newTestServer(t)
	for i := 0; i < loginMaxFailures; i++ {
		if code := call(t, ts, "", "POST", "/api/v1/auth/login", loginRequest{"admin", "wrong"}, nil); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := call(t, ts, "", "POST", "/api/v1/auth/login", loginRequest{"admin", adminPassword}, nil); code != http.StatusTooManyRequests {
		t.Errorf("after lockout: %d", code)
	}
}

func TestSPAHandler(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("INDEX"), 0o644)
	os.Mkdir(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("JS"), 0o644)
	ts := httptest.NewServer(spaHandler(dir))
	defer ts.Close()

	for path, want := range map[string]string{
		"/":              "INDEX",
		"/assets":        "INDEX", // 前端路由，不能被当成目录
		"/assets/":       "INDEX",
		"/alerts":        "INDEX",
		"/assets/app.js": "JS",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Errorf("GET %s = %d %q, want %q", path, resp.StatusCode, body, want)
		}
	}

	// 路径穿越直接拒绝。
	resp, err := http.Get(ts.URL + "/../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("path traversal: %d", resp.StatusCode)
	}
}
