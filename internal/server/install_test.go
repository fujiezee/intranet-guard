package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testPin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestInstallEndpoints(t *testing.T) {
	_, adminToken, st := newTestServerWithStore(t)
	dist := t.TempDir()
	os.WriteFile(filepath.Join(dist, "safe-agent-linux-amd64"), []byte("BINARY"), 0o755)
	os.WriteFile(filepath.Join(dist, "secret.txt"), []byte("nope"), 0o600)
	srv := New(Config{InstallPin: testPin, NodePort: 8443, DistDir: dist}, st)
	nodes := httptest.NewServer(srv.NodeHandler())
	defer nodes.Close()
	console := httptest.NewServer(srv)
	defer console.Close()

	get := func(path, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", nodes.URL+path, nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	for _, kind := range []string{"agent", "probe"} {
		code, script := get("/install/"+kind+".sh", "10.1.2.3:8443")
		if code != http.StatusOK || !strings.Contains(script, "SERVER='https://10.1.2.3:8443'") ||
			!strings.Contains(script, "PIN='"+testPin+"'") || !strings.Contains(script, "KIND='"+kind+"'") {
			t.Fatalf("%s script: %d\n%s", kind, code, script)
		}
		// 渲染出的脚本必须是合法的 sh。
		f := filepath.Join(t.TempDir(), kind+".sh")
		os.WriteFile(f, []byte(script), 0o644)
		if out, err := exec.Command("sh", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s script syntax: %v\n%s", kind, err, out)
		}
		checkShellVars(t, kind+".sh", script)
		if kind == "probe" && !strings.Contains(script, "SAFE_PROBE_ID") {
			t.Error("probe script does not require SAFE_PROBE_ID")
		}
	}

	// Host 头会写进脚本，含引号等字符时拒绝（防止注入命令）。
	if code, _ := get("/install/agent.sh", "evil';rm -rf /;'"); code != http.StatusBadRequest {
		t.Errorf("malicious host: %d", code)
	}
	if code, _ := get("/install/other.sh", ""); code != http.StatusNotFound {
		t.Errorf("unknown script: %d", code)
	}

	if code, body := get("/download/safe-agent-linux-amd64", ""); code != http.StatusOK || body != "BINARY" {
		t.Errorf("download: %d %q", code, body)
	}
	for _, bad := range []string{"/download/secret.txt", "/download/..%2Fsecret.txt", "/download/safe-probe-linux-amd64"} {
		if code, _ := get(bad, ""); code != http.StatusNotFound {
			t.Errorf("GET %s: %d", bad, code)
		}
	}

	var info installInfo
	if code := call(t, console, adminToken, "GET", "/api/v1/install-info", nil, &info); code != http.StatusOK ||
		info.Pin != testPin || info.NodePort != 8443 || len(info.Available) != 1 {
		t.Errorf("install-info: %d %+v", code, info)
	}
}

// 某些 shell（如 macOS 的 bash 3.2、部分 locale 下的 bash）会把紧跟在 $VAR 后面的非 ASCII 字节当作变量名的一部分，
// 在 set -u 下直接报错退出。脚本里变量后紧跟中文时必须写成 ${VAR}。
var unbracedBeforeNonASCII = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7f]`)

func checkShellVars(t *testing.T, name, script string) {
	t.Helper()
	for i, line := range strings.Split(script, "\n") {
		if m := unbracedBeforeNonASCII.FindString(line); m != "" {
			t.Errorf("%s:%d: variable followed by non-ASCII text, use ${...}: %q", name, i+1, m)
		}
	}
}

func TestShellScriptsVarBraces(t *testing.T) {
	for _, f := range []string{"../../scripts/install.sh", "../../scripts/backup.sh", "../../scripts/test-install.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checkShellVars(t, filepath.Base(f), string(b))
		if out, err := exec.Command("sh", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s syntax: %v\n%s", f, err, out)
		}
	}
}
