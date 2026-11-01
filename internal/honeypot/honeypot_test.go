package honeypot

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"safe/internal/model"
)

type recorder struct {
	mu     sync.Mutex
	events []model.HoneypotEvent
}

func (r *recorder) emit(e model.HoneypotEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) wait(t *testing.T, n int) []model.HoneypotEvent {
	t.Helper()
	for i := 0; i < 50; i++ {
		r.mu.Lock()
		if len(r.events) >= n {
			out := append([]model.HoneypotEvent(nil), r.events...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Fatalf("got %d events, want %d: %+v", len(r.events), n, r.events)
	return nil
}

func freePort(t *testing.T) int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// start 启动单个服务的蜜罐；testRemote 为 true 时把本机地址当作外部来源（测试只能从本机连接）。
func start(t *testing.T, typ string, testRemote bool) (*Manager, *recorder, string) {
	t.Helper()
	rec := &recorder{}
	m := New(rec.emit)
	port := freePort(t)
	m.Apply(model.HoneypotConfig{Enabled: true, Services: []model.HoneypotService{{Type: typ, Port: port}}})
	if testRemote {
		m.mu.Lock()
		m.local = map[netip.Addr]bool{}
		m.mu.Unlock()
	}
	t.Cleanup(m.Close)
	if st := m.Status()[port]; st != "listening" {
		t.Fatalf("status = %q", st)
	}
	return m, rec, fmt.Sprintf("127.0.0.1:%d", port)
}

func TestSSH(t *testing.T) {
	_, rec, addr := start(t, "ssh", true)
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("toor123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
	if err == nil {
		t.Fatal("honeypot accepted a login")
	}
	var found bool
	for _, e := range rec.wait(t, 2) {
		if e.Username == "root" && e.Password == "t******" && e.Service == "ssh" && e.SrcIP == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("password attempt not recorded: %+v", rec.events)
	}
}

func TestFTPAndTelnet(t *testing.T) {
	_, rec, addr := start(t, "ftp", true)
	c, _ := net.Dial("tcp", addr)
	r := bufio.NewReader(c)
	r.ReadString('\n')
	fmt.Fprint(c, "USER admin\r\n")
	r.ReadString('\n')
	fmt.Fprint(c, "PASS secret\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "530") {
		t.Errorf("ftp reply %q", line)
	}
	c.Close()
	if e := rec.wait(t, 1)[0]; e.Username != "admin" || e.Password != "s*****" {
		t.Errorf("ftp event %+v", e)
	}

	_, rec, addr = start(t, "telnet", true)
	c, _ = net.Dial("tcp", addr)
	r = bufio.NewReader(c)
	r.ReadString(':')
	fmt.Fprint(c, "\xff\xfb\x01oracle\r\n") // 带 IAC 协商字节
	r.ReadString(':')
	fmt.Fprint(c, "oracle\r\n")
	c.Close()
	if e := rec.wait(t, 1)[0]; e.Username != "oracle" || e.Password != "o*****" {
		t.Errorf("telnet event %+v", e)
	}
}

func TestMySQL(t *testing.T) {
	_, rec, addr := start(t, "mysql", true)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	head := make([]byte, 4)
	io.ReadFull(c, head)
	hs := make([]byte, int(head[0])|int(head[1])<<8)
	io.ReadFull(c, hs)
	if hs[0] != 10 || !strings.HasPrefix(string(hs[1:]), "5.7") {
		t.Fatalf("handshake %q", hs[:12])
	}
	payload := append(make([]byte, 32), []byte("dbadmin\x00")...)
	c.Write(mysqlPacket(1, payload))
	io.ReadFull(c, head)
	errp := make([]byte, int(head[0]))
	io.ReadFull(c, errp)
	if errp[0] != 0xff || !strings.Contains(string(errp), "Access denied for user 'dbadmin'") {
		t.Errorf("error packet %q", errp)
	}
	if e := rec.wait(t, 1)[0]; e.Username != "dbadmin" {
		t.Errorf("mysql event %+v", e)
	}
}

func TestRedis(t *testing.T) {
	_, rec, addr := start(t, "redis", true)
	c, _ := net.Dial("tcp", addr)
	r := bufio.NewReader(c)
	fmt.Fprint(c, "*2\r\n$4\r\nAUTH\r\n$6\r\nfoobar\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "-WRONGPASS") {
		t.Errorf("auth reply %q", line)
	}
	fmt.Fprint(c, "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n")
	r.ReadString('\n')
	c.Close()
	ev := rec.wait(t, 2)
	if ev[0].Password != "f*****" || !strings.Contains(ev[1].Detail, "CONFIG SET dir /var/spool/cron/") {
		t.Errorf("redis events %+v", ev)
	}
}

func TestHTTP(t *testing.T) {
	_, rec, addr := start(t, "http", true)
	resp, err := http.Get("http://" + addr + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "运维管理平台") || strings.Contains(string(page), "%!") {
		t.Errorf("login page broken: %s", page)
	}
	resp, err = http.PostForm("http://"+addr+"/login", url.Values{"username": {"admin"}, "password": {"Admin@123"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("login status %d", resp.StatusCode)
	}
	ev := rec.wait(t, 2)
	if !strings.Contains(ev[0].Detail, "GET /admin") || ev[1].Username != "admin" || ev[1].Password != "A********" {
		t.Errorf("http events %+v", ev)
	}
}

func TestTCPProtocolGuess(t *testing.T) {
	_, rec, addr := start(t, "tcp", true)
	c, _ := net.Dial("tcp", addr)
	c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00})
	c.Close()
	if e := rec.wait(t, 1)[0]; !strings.Contains(e.Detail, "RDP") {
		t.Errorf("tcp event %+v", e)
	}
}

// 本机来源（探针自己的扫描）被忽略；自检标记的连接即使来自本机也上报。
func TestLocalIgnoredButSimulationReported(t *testing.T) {
	_, rec, addr := start(t, "http", false)
	if resp, err := http.Get("http://" + addr + "/"); err == nil {
		resp.Body.Close()
	}
	time.Sleep(200 * time.Millisecond)
	if len(rec.events) != 0 {
		t.Fatalf("local scan reported: %+v", rec.events)
	}
	c, _ := net.Dial("tcp", addr)
	fmt.Fprint(c, SimulationMarker+"sim-0123abcd\n")
	reply, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	ev := rec.wait(t, 1)
	if reply != "OK\n" || ev[0].SimulationID != "sim-0123abcd" {
		t.Errorf("simulation: reply %q events %+v", reply, ev)
	}
}

func TestIgnoreSourcesAndRateLimit(t *testing.T) {
	m, rec, addr := start(t, "tcp", true)
	m.Apply(model.HoneypotConfig{Enabled: true, IgnoreSources: []string{"127.0.0.0/8"},
		Services: []model.HoneypotService{{Type: "tcp", Port: mustPort(addr)}}})
	c, _ := net.Dial("tcp", addr)
	c.Write([]byte("x"))
	c.Close()
	time.Sleep(200 * time.Millisecond)
	if len(rec.events) != 0 {
		t.Fatalf("ignored source reported: %+v", rec.events)
	}

	m.Apply(model.HoneypotConfig{Enabled: true, Services: []model.HoneypotService{{Type: "tcp", Port: mustPort(addr)}}})
	m.mu.Lock()
	m.local = map[netip.Addr]bool{}
	m.mu.Unlock()
	for i := 0; i < maxEventsPerIP+10; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("x"))
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
	rec.mu.Lock()
	n := len(rec.events)
	rec.mu.Unlock()
	if n != maxEventsPerIP {
		t.Errorf("rate limit: %d events, want %d", n, maxEventsPerIP)
	}

	m.Apply(model.HoneypotConfig{Enabled: false})
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("listener still open after disable")
	}
}

func mustPort(addr string) int {
	ap := netip.MustParseAddrPort(addr)
	return int(ap.Port())
}
