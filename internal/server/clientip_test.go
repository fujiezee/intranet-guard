package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	s := &Server{cfg: Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}
	tests := []struct {
		name, remote, xff, want string
	}{
		{"direct client ignores header", "192.168.1.5:1234", "1.2.3.4", "192.168.1.5"},
		{"trusted proxy", "10.0.0.2:5555", "192.168.1.9", "192.168.1.9"},
		{"spoofed left part ignored", "10.0.0.2:5555", "6.6.6.6, 192.168.1.9", "192.168.1.9"},
		{"chained trusted proxies", "10.0.0.2:5555", "192.168.1.9, 10.0.0.3", "192.168.1.9"},
		{"proxy without header", "10.0.0.2:5555", "", "10.0.0.2"},
		{"malformed header falls back to proxy", "10.0.0.2:5555", "not-an-ip", "10.0.0.2"},
		{"ipv4-mapped proxy address", "[::ffff:10.0.0.2]:5555", "192.168.1.9", "192.168.1.9"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remote
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := s.clientIP(r); got != tt.want {
			t.Errorf("%s: clientIP = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// 代理后面的登录限流必须按真实客户端计数，否则一个人输错密码会把所有人锁住。
func TestLoginLimiterBehindProxy(t *testing.T) {
	ts, _, st := newTestServerWithStore(t)
	ts.Close()
	srv := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, st)
	ts = httptest.NewServer(srv)
	defer ts.Close()

	login := func(xff, password string) int {
		body, _ := json.Marshal(loginRequest{"admin", password})
		r, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login", bytes.NewReader(body))
		r.Header.Set("X-Forwarded-For", xff)
		resp, err := ts.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < loginMaxFailures; i++ {
		login("192.168.1.66", "wrong")
	}
	if code := login("192.168.1.66", adminPassword); code != 429 {
		t.Errorf("attacker not locked out: %d", code)
	}
	if code := login("192.168.1.10", adminPassword); code != 200 {
		t.Errorf("other user behind same proxy locked out: %d", code)
	}
}
