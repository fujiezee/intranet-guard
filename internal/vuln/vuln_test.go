package vuln

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"safe/internal/model"
)

var fast = Options{Timeout: time.Second, AttemptDelay: time.Millisecond}

// serve 在本地端口上运行一个简单的 TCP 服务，返回地址。
func serve(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().String()
}

// fakeRedis 模拟 Redis：password 为空时无需认证。
func fakeRedis(password string) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		authed := password == ""
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
			var args []string
			for i := 0; i < n; i++ {
				r.ReadString('\n')
				a, _ := r.ReadString('\n')
				args = append(args, strings.TrimSpace(a))
			}
			switch {
			case args[0] == "AUTH" && args[1] == password:
				authed = true
				c.Write([]byte("+OK\r\n"))
			case args[0] == "AUTH":
				c.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
			case !authed:
				c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			default:
				body := "# Server\r\nredis_version:7.2.4\r\n"
				fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
			}
		}
	}
}

func ids(results []model.CheckResult) map[string]bool {
	out := map[string]bool{}
	for _, r := range results {
		out[r.CheckID] = r.Vulnerable
	}
	return out
}

func TestRedis(t *testing.T) {
	ctx := context.Background()
	got := ids(checkRedis(ctx, serve(t, fakeRedis("")), fast))
	if !got["redis-unauth"] {
		t.Errorf("unauth redis not detected: %v", got)
	}

	weak := Options{WeakPassword: true, Timeout: time.Second, AttemptDelay: time.Millisecond}
	got = ids(checkRedis(ctx, serve(t, fakeRedis("foobared")), weak))
	if v, ok := got["redis-unauth"]; !ok || v || !got["redis-weak-password"] {
		t.Errorf("weak password redis: %v", got)
	}

	got = ids(checkRedis(ctx, serve(t, fakeRedis("Str0ng-and-l0ng!")), weak))
	if v, ok := got["redis-weak-password"]; !ok || v {
		t.Errorf("strong password redis: %v", got)
	}
	// 未开启弱口令检测时不尝试 AUTH，也不对弱口令下结论。
	got = ids(checkRedis(ctx, serve(t, fakeRedis("foobared")), fast))
	if _, ok := got["redis-weak-password"]; ok {
		t.Errorf("weak password checked without opt-in: %v", got)
	}
}

func TestMemcached(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("STAT pid 1234\r\nSTAT uptime 5\r\nEND\r\n"))
	})
	if !ids(checkMemcached(context.Background(), addr, fast))["memcached-unauth"] {
		t.Error("memcached not detected")
	}
}

func TestHTTPAPIs(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cluster_name":"logs","version":{"number":"7.17.0"}}`))
	}))
	defer es.Close()
	secured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer secured.Close()
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Write([]byte(`{"Version":"24.0.7","ApiVersion":"1.43"}`))
		}
	}))
	defer docker.Close()
	host := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }
	ctx := context.Background()

	if !ids(checkElasticsearch(ctx, host(es), fast))["elasticsearch-unauth"] {
		t.Error("open elasticsearch not detected")
	}
	if v, ok := ids(checkElasticsearch(ctx, host(secured), fast))["elasticsearch-unauth"]; !ok || v {
		t.Error("secured elasticsearch should be checked and not vulnerable")
	}
	if !ids(checkDockerAPI(ctx, host(docker), fast))["docker-api-unauth"] {
		t.Error("docker API not detected")
	}
}

// fakeFTP 模拟 FTP：anonymous 是否允许，以及一组有效账号。
func fakeFTP(anonymous bool, user, pass string) func(net.Conn) {
	return func(c net.Conn) {
		c.Write([]byte("220-Welcome\r\n220 (vsFTPd 3.0.5)\r\n"))
		r := bufio.NewReader(c)
		var u string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch cmd {
			case "USER":
				u = arg
				c.Write([]byte("331 Please specify the password.\r\n"))
			case "PASS":
				if (u == "anonymous" && anonymous) || (u == user && arg == pass) {
					c.Write([]byte("230 Login successful.\r\n"))
				} else {
					c.Write([]byte("530 Login incorrect.\r\n"))
				}
			case "QUIT":
				c.Write([]byte("221 Goodbye.\r\n"))
				return
			}
		}
	}
}

func TestFTP(t *testing.T) {
	ctx := context.Background()
	weak := Options{WeakPassword: true, Timeout: time.Second, AttemptDelay: time.Millisecond}

	got := ids(checkFTP(ctx, serve(t, fakeFTP(true, "", "")), fast))
	if !got["ftp-anonymous"] {
		t.Errorf("anonymous FTP not detected: %v", got)
	}
	got = ids(checkFTP(ctx, serve(t, fakeFTP(false, "admin", "admin")), weak))
	if v, ok := got["ftp-anonymous"]; !ok || v || !got["ftp-weak-password"] {
		t.Errorf("weak FTP: %v", got)
	}
	got = ids(checkFTP(ctx, serve(t, fakeFTP(false, "admin", "S3cure-pass")), weak))
	if v, ok := got["ftp-weak-password"]; !ok || v {
		t.Errorf("strong FTP: %v", got)
	}
}

// sshServer 启动只接受指定账号密码的 SSH 服务，并统计登录尝试次数。
func sshServer(t *testing.T, user, pass string, attempts *int) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		*attempts++
		if c.User() == user && string(p) == pass {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	return serve(t, func(c net.Conn) {
		sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "no")
		}
		sc.Close()
	})
}

func TestSSH(t *testing.T) {
	ctx := context.Background()
	weak := Options{WeakPassword: true, Timeout: 2 * time.Second, AttemptDelay: time.Millisecond}

	var n int
	got := checkSSH(ctx, sshServer(t, "admin", "admin", &n), weak)
	if len(got) != 1 || !got[0].Vulnerable {
		t.Fatalf("weak SSH: %+v", got)
	}
	if !strings.HasSuffix(got[0].Detail, "弱口令 a****") {
		t.Errorf("password not masked: %q", got[0].Detail)
	}

	n = 0
	got = checkSSH(ctx, sshServer(t, "root", "V3ry-strong-pass", &n), weak)
	if len(got) != 1 || got[0].Vulnerable {
		t.Errorf("strong SSH: %+v", got)
	}
	// 失败次数必须低于爆破告警阈值。
	if n >= 10 || n != len(SSHCredentials) {
		t.Errorf("SSH attempts = %d", n)
	}
	if got := checkSSH(ctx, "127.0.0.1:1", fast); got != nil {
		t.Errorf("SSH checked without opt-in: %+v", got)
	}
}

func TestBannerRules(t *testing.T) {
	tests := []struct {
		banner string
		id     string
		vuln   bool
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "CVE-2024-6387", true},
		{"SSH-2.0-OpenSSH_8.5p1", "CVE-2024-6387", true},
		{"SSH-2.0-OpenSSH_9.8p1", "CVE-2024-6387", false},
		{"SSH-2.0-OpenSSH_8.4p1", "CVE-2024-6387", false},
		{"SSH-2.0-OpenSSH_10.0", "CVE-2024-6387", false},
		{"220 (vsFTPd 2.3.4)", "CVE-2011-2523", true},
		{"220 (vsFTPd 3.0.5)", "CVE-2011-2523", false},
		{"220 ProFTPD 1.3.5 Server (Debian)", "CVE-2015-3306", true},
		{"220 ProFTPD 1.3.5a Server", "CVE-2015-3306", false},
	}
	for _, tt := range tests {
		res := CheckBanners([]model.Asset{{IP: "10.0.0.1", Ports: []model.Port{{Port: 22, Banner: tt.banner}}}})
		if len(res) != 1 || res[0].CheckID != tt.id || res[0].Vulnerable != tt.vuln {
			t.Errorf("%q: %+v", tt.banner, res)
		}
	}
	if res := CheckBanners([]model.Asset{{IP: "10.0.0.1", Ports: []model.Port{{Port: 80, Banner: "nginx"}}}}); len(res) != 0 {
		t.Errorf("unrelated banner: %+v", res)
	}
}

func TestRunDispatch(t *testing.T) {
	redisAddr := serve(t, fakeRedis(""))
	host, portStr, _ := net.SplitHostPort(redisAddr)
	port, _ := strconv.Atoi(portStr)
	// 非标准端口靠 service 名识别。
	res := Run(context.Background(), []model.Asset{{IP: host, Ports: []model.Port{{Port: port, Service: "redis"}}}}, fast)
	if len(res) != 1 || res[0].IP != host || res[0].Port != port || !res[0].Vulnerable {
		t.Errorf("Run = %+v", res)
	}
}
