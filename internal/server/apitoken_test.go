package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tokenCall(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

func TestAPITokenIsReadOnly(t *testing.T) {
	ts, admin := newTestServer(t)
	code, body := tokenCall(t, ts, "POST", "/api/v1/api-tokens", admin, `{"name":"claude"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created struct {
		Token    string `json:"token"`
		APIToken struct {
			ID int64 `json:"id"`
		} `json:"api_token"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"/api/v1/stats", "/api/v1/alerts", "/api/v1/assets", "/api/v1/incidents"} {
		if code, body := tokenCall(t, ts, "GET", p, created.Token, ""); code != http.StatusOK {
			t.Errorf("GET %s: %d %s", p, code, body)
		}
	}
	// 管理员接口和所有写操作（包括只读用户能做的改密码、退出）都拒绝
	for _, c := range [][2]string{
		{"GET", "/api/v1/users"}, {"GET", "/api/v1/audit"}, {"GET", "/api/v1/api-tokens"},
		{"POST", "/api/v1/api-tokens"}, {"POST", "/api/v1/tasks"}, {"POST", "/api/v1/actions"},
		{"POST", "/api/v1/auth/password"}, {"POST", "/api/v1/auth/logout"},
	} {
		if code, _ := tokenCall(t, ts, c[0], c[1], created.Token, `{}`); code != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403", c[0], c[1], code)
		}
	}
	if code, body := tokenCall(t, ts, "GET", "/api/v1/api-tokens", admin, ""); code != http.StatusOK ||
		strings.Contains(body, created.Token) || !strings.Contains(body, "last_used_at") {
		t.Errorf("list: %d %s", code, body)
	}

	if code, _ := tokenCall(t, ts, "GET", "/api/v1/stats", "safe_ro_wrong", ""); code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", code)
	}
	if code, _ := tokenCall(t, ts, "DELETE", "/api/v1/api-tokens/1", admin, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := tokenCall(t, ts, "GET", "/api/v1/stats", created.Token, ""); code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", code)
	}
}
