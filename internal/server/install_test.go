package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"safe/internal/pki"
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

	// Windows 脚本：管理中心地址写入单引号字符串
	if code, script := get("/install/agent.ps1", "10.1.2.3:8443"); code != http.StatusOK ||
		!strings.Contains(script, "$Server = 'https://10.1.2.3:8443'") || strings.Contains(script, "{{") {
		t.Errorf("windows script: %d", code)
	}
	if code, _ := get("/install/agent.ps1", "evil';calc;'"); code != http.StatusBadRequest {
		t.Errorf("malicious host for windows script: %d", code)
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
	os.WriteFile(filepath.Join(dist, "safe-agent-windows-amd64.exe"), []byte("MZ"), 0o755)
	if code := call(t, console, adminToken, "GET", "/api/v1/install-info", nil, &info); code != http.StatusOK ||
		info.Pin != testPin || info.NodePort != 8443 || len(info.Available) != 2 {
		t.Errorf("install-info: %d %+v", code, info)
	}
	// Windows 命令：主机名取自访问控制台的地址，端口为节点端口；指纹去掉 sha256// 前缀
	host := strings.TrimPrefix(console.URL, "http://")
	host = host[:strings.LastIndex(host, ":")]
	if !strings.Contains(info.WindowsCommand, "DownloadString('https://"+host+":8443/install/agent.ps1')") ||
		!strings.Contains(info.WindowsCommand, "-eq '"+strings.TrimPrefix(testPin, "sha256//")+"'") ||
		!strings.Contains(info.WindowsCommand, "SAFE_ENROLL_TOKEN='__TOKEN__'") {
		t.Errorf("windows command: %s", info.WindowsCommand)
	}
	if code, body := get("/download/safe-agent-windows-amd64.exe", ""); code != http.StatusOK || body != "MZ" {
		t.Errorf("windows download: %d %q", code, body)
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
	for _, f := range []string{"../../scripts/install.sh", "../../scripts/backup.sh", "../../scripts/test-install.sh", "../../scripts/e2e-linux.sh"} {
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

// PowerShell 5.1 只能取得证书中的原始公钥（65 字节的未压缩点），命令里拼上固定前缀再计算 SHA-256；
// 这里确认结果与 curl --pinnedpubkey 使用的 SubjectPublicKeyInfo 指纹完全一致。
func TestWindowsPinMatchesSPKI(t *testing.T) {
	key, err := pki.LoadOrCreateServerKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := pki.PublicKeyPin(key)
	ecdhKey, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	var spki []byte
	for _, b := range strings.Split(p256SPKIPrefix, ",") {
		v, err := strconv.ParseUint(strings.TrimPrefix(b, "0x"), 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		spki = append(spki, byte(v))
	}
	spki = append(spki, ecdhKey.Bytes()...)
	sum := sha256.Sum256(spki)
	if got := "sha256//" + base64.StdEncoding.EncodeToString(sum[:]); got != pin {
		t.Fatalf("powershell pin %s != spki pin %s", got, pin)
	}
}
