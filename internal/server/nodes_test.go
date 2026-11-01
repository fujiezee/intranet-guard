package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/node"
	"safe/internal/pki"
	"safe/internal/store"
	"safe/internal/store/storetest"
)

type nodeEnv struct {
	console    *httptest.Server
	nodes      *httptest.Server
	adminToken string
	st         *store.Store
}

func newNodeEnv(t *testing.T) nodeEnv {
	t.Helper()
	st := storetest.Open(t)
	hash, _ := HashPassword(adminPassword)
	st.CreateUser(context.Background(), "admin", hash, model.RoleAdmin)

	ca, _, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{CA: ca}, st)
	console := httptest.NewServer(srv)
	t.Cleanup(console.Close)

	nodes := httptest.NewUnstartedServer(srv.NodeHandler())
	if nodes.TLS, err = NodeTLSConfig(ca, []string{"127.0.0.1"}, nil); err != nil {
		t.Fatal(err)
	}
	nodes.StartTLS()
	t.Cleanup(nodes.Close)
	return nodeEnv{console: console, nodes: nodes, adminToken: login(t, console, "admin", adminPassword), st: st}
}

func (e nodeEnv) token(t *testing.T, kind model.NodeKind, maxUses int) string {
	t.Helper()
	var resp createEnrollTokenResponse
	if code := call(t, e.console, e.adminToken, "POST", "/api/v1/enroll-tokens",
		createEnrollTokenRequest{Kind: kind, MaxUses: maxUses, TTLHours: 1}, &resp); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}
	return resp.Token
}

func (e nodeEnv) connect(t *testing.T, kind model.NodeKind, id, token, dir string) (*node.Client, error) {
	t.Helper()
	t.Setenv("SAFE_ENROLL_TOKEN", token)
	return node.Connect(context.Background(), string(kind), id, dir, e.nodes.URL)
}

// nodeCall 用节点客户端调用接入端口，返回状态码。
func nodeCall(t *testing.T, hc *http.Client, url, method string, body any) int {
	t.Helper()
	var buf strings.Builder
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req, _ := http.NewRequest(method, url, strings.NewReader(buf.String()))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestNodeEnrollmentAndMTLS(t *testing.T) {
	e := newNodeEnv(t)
	agentToken := e.token(t, model.NodeAgent, 2)
	report := func(id string) model.AgentReport {
		return model.AgentReport{Agent: model.AgentInfo{ID: id, Hostname: id}, Events: []model.HostEvent{}}
	}

	// 令牌里的 CA 指纹不匹配（模拟连到了冒充的服务器）：拒绝注册。
	secret, _, _ := strings.Cut(agentToken, ".")
	if _, err := e.connect(t, model.NodeAgent, "web01", secret+"."+strings.Repeat("0", 64), t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong fingerprint: %v", err)
	}
	// 错误的令牌。
	if _, err := e.connect(t, model.NodeAgent, "web01", strings.Repeat("a", 32)+agentToken[32:], t.TempDir()); err == nil {
		t.Fatal("bad secret accepted")
	}
	// 代理令牌不能注册探针。
	if _, err := e.connect(t, model.NodeProbe, "seg-x", agentToken, t.TempDir()); err == nil {
		t.Fatal("agent token enrolled a probe")
	}

	dir1 := t.TempDir()
	web01, err := e.connect(t, model.NodeAgent, "web01", agentToken, dir1)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir1, "node.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key permissions = %v", fi.Mode().Perm())
	}
	url := e.nodes.URL + "/api/v1/agent/report"
	if code := nodeCall(t, web01.HTTP, url, "POST", report("web01")); code != http.StatusOK {
		t.Fatalf("report as self: %d", code)
	}
	if code := nodeCall(t, web01.HTTP, url, "POST", report("db01")); code != http.StatusForbidden {
		t.Errorf("impersonation: %d", code)
	}
	if code := nodeCall(t, web01.HTTP, e.nodes.URL+"/api/v1/probe/tasks", "GET", nil); code != http.StatusForbidden {
		t.Errorf("agent cert on probe API: %d", code)
	}

	// 无证书访问。
	noCert := &http.Client{Transport: e.nodes.Client().Transport}
	if code := nodeCall(t, noCert, url, "POST", report("web01")); code != http.StatusUnauthorized {
		t.Errorf("no client cert: %d", code)
	}

	// 已注册的 ID 不能被再次注册（防止用新证书顶替）；令牌用完后失效。
	if _, err := e.connect(t, model.NodeAgent, "web01", agentToken, t.TempDir()); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("re-enroll active id: %v", err)
	}
	if _, err := e.connect(t, model.NodeAgent, "web02", agentToken, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.connect(t, model.NodeAgent, "web03", agentToken, t.TempDir()); err == nil {
		t.Error("token used beyond max_uses")
	}

	// 续期：新证书可用，旧证书立即失效。
	oldDir := t.TempDir()
	for _, f := range []string{"node.key", "node.crt", "ca.crt"} {
		b, _ := os.ReadFile(filepath.Join(dir1, f))
		os.WriteFile(filepath.Join(oldDir, f), b, 0o600)
	}
	oldClient, err := node.Connect(context.Background(), "agent", "web01", oldDir, e.nodes.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := web01.Renew(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if code := nodeCall(t, web01.HTTP, url, "POST", report("web01")); code != http.StatusOK {
		t.Errorf("after renew: %d", code)
	}
	if code := nodeCall(t, oldClient.HTTP, url, "POST", report("web01")); code != http.StatusUnauthorized {
		t.Errorf("superseded cert still accepted: %d", code)
	}

	// 吊销后立即拒绝；吊销后允许重新注册。
	if code := call(t, e.console, e.adminToken, "POST", "/api/v1/nodes/agent/web01/revoke", nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code := nodeCall(t, web01.HTTP, url, "POST", report("web01")); code != http.StatusUnauthorized {
		t.Errorf("revoked cert accepted: %d", code)
	}
	if _, err := e.connect(t, model.NodeAgent, "web01", e.token(t, model.NodeAgent, 1), t.TempDir()); err != nil {
		t.Errorf("re-enroll after revoke: %v", err)
	}

	var nodes []model.Node
	call(t, e.console, e.adminToken, "GET", "/api/v1/nodes", nil, &nodes)
	if len(nodes) != 2 {
		t.Errorf("nodes = %+v", nodes)
	}
	for _, n := range nodes {
		if n.Status != model.NodeActive || time.Until(n.CertExpiry) < 300*24*time.Hour {
			t.Errorf("node = %+v", n)
		}
	}
}

func TestProbeIdentity(t *testing.T) {
	e := newNodeEnv(t)
	probe, err := e.connect(t, model.NodeProbe, "seg-a", e.token(t, model.NodeProbe, 1), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var task model.ScanTask
	call(t, e.console, e.adminToken, "POST", "/api/v1/tasks", createTaskRequest{ProbeID: "seg-b", Targets: []string{"10.0.0.1"}}, &task)

	if code := nodeCall(t, probe.HTTP, e.nodes.URL+"/api/v1/probe/tasks?probe_id=seg-b", "GET", nil); code != http.StatusForbidden {
		t.Errorf("claim other probe's tasks: %d", code)
	}
	if code := nodeCall(t, probe.HTTP, e.nodes.URL+"/api/v1/probe/reports", "POST",
		model.ScanReport{TaskID: task.ID, ProbeID: "seg-b"}); code != http.StatusForbidden {
		t.Errorf("report for other probe: %d", code)
	}
	// 不填 probe_id 时以证书为准。
	if code := nodeCall(t, probe.HTTP, e.nodes.URL+"/api/v1/probe/tasks", "GET", nil); code != http.StatusOK {
		t.Errorf("claim own tasks: %d", code)
	}
	// 控制台端口不再接受节点请求（未配置旧版 token）。
	if code := call(t, e.console, "", "GET", "/api/v1/probe/tasks?probe_id=seg-a", nil, nil); code != http.StatusNotFound {
		t.Errorf("legacy route without tokens: %d", code)
	}
}
