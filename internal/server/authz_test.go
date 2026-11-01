package server

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// publicConsoleRoutes 是控制台端口上不需要登录的全部接口，新增时必须在这里说明。
var publicConsoleRoutes = map[string]bool{"POST /api/v1/auth/login": true}

// viewerRoutes 是只读用户可以访问的全部接口。写在这里而不是从 server.go 读取：
// 把管理员接口误改成 viewer 时，这份名单让测试失败。
var viewerRoutes = map[string]bool{
	"POST /api/v1/auth/logout":                true,
	"GET /api/v1/auth/me":                     true,
	"POST /api/v1/auth/password":              true,
	"GET /api/v1/stats":                       true,
	"GET /api/v1/tasks":                       true,
	"GET /api/v1/tasks/{id}":                  true,
	"GET /api/v1/validation/coverage":         true,
	"GET /api/v1/validation/scopes":           true,
	"GET /api/v1/validation/runs":             true,
	"GET /api/v1/validation/runs/{id}/report": true,
	"GET /api/v1/assets":                      true,
	"GET /api/v1/assets/{ip}":                 true,
	"GET /api/v1/alerts":                      true,
	"GET /api/v1/vulns":                       true,
	"GET /api/v1/rules":                       true,
	"GET /api/v1/honeypots":                   true,
	"GET /api/v1/honeypot-events":             true,
	"GET /api/v1/simulations":                 true,
	"GET /api/v1/intel":                       true,
	"GET /api/v1/intel/feeds":                 true,
	"GET /api/v1/intel/net-config":            true,
	"GET /api/v1/incidents":                   true,
	"GET /api/v1/incidents/{id}":              true,
	"GET /api/v1/version":                     true,
	"GET /api/v1/upgrades":                    true,
	"GET /api/v1/groups":                      true,
	"GET /api/v1/actions":                     true,
	"GET /api/v1/agents":                      true,
	"GET /api/v1/host-events":                 true,
	"GET /api/v1/ids/events":                  true,
	"GET /api/v1/ids/suppressions":            true,
}

var routeRe = regexp.MustCompile(`s\.mux\.(Handle|HandleFunc)\("([A-Z]+ /api/[^"]+)",\s*(\w+)?`)

// 从 server.go 读出全部路由，新增接口自动纳入检查：不用维护清单，也不会漏掉。
func TestEveryConsoleRouteRequiresItsRole(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	ts, adminTok := newTestServer(t)
	_, body := tokenCall(t, ts, "POST", "/api/v1/users", adminTok, `{"username":"reader","password":"reader-password","role":"viewer"}`)
	if !strings.Contains(body, "reader") {
		t.Fatal(body)
	}
	viewerTok := login(t, ts, "reader", "reader-password")
	_, body = tokenCall(t, ts, "POST", "/api/v1/api-tokens", adminTok, `{"name":"authz"}`)
	apiTok := regexp.MustCompile(`safe_ro_[0-9a-f]+`).FindString(body)
	if apiTok == "" {
		t.Fatal(body)
	}

	matches := routeRe.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 50 {
		t.Fatalf("found only %d routes: pattern out of date?", len(matches))
	}
	for _, m := range matches {
		kind, route, wrapper := m[1], m[2], m[3]
		if publicConsoleRoutes[route] {
			continue
		}
		if kind != "Handle" || (wrapper != "admin" && wrapper != "viewer") {
			t.Errorf("%s has no role check", route)
			continue
		}
		if wrapper == "viewer" && !viewerRoutes[route] {
			t.Errorf("%s is open to viewers but not listed in viewerRoutes", route)
		}
		method, path, _ := strings.Cut(route, " ")
		path = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "1")

		if code, _ := tokenCall(t, ts, method, path, "", `{}`); code != http.StatusUnauthorized {
			t.Errorf("%s without session: %d, want 401", route, code)
		}
		if code, _ := tokenCall(t, ts, method, path, "safe_ro_invalid", `{}`); code != http.StatusUnauthorized {
			t.Errorf("%s with unknown token: %d, want 401", route, code)
		}
		if wrapper == "admin" {
			if code, _ := tokenCall(t, ts, method, path, viewerTok, `{}`); code != http.StatusForbidden {
				t.Errorf("%s as viewer: %d, want 403", route, code)
			}
		}
		if wrapper == "admin" || method != http.MethodGet {
			if code, _ := tokenCall(t, ts, method, path, apiTok, `{}`); code != http.StatusForbidden {
				t.Errorf("%s with API token: %d, want 403", route, code)
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := ts.Client().Get(ts.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), want) {
			t.Errorf("CSP missing %q: %q", want, resp.Header.Get("Content-Security-Policy"))
		}
	}
}

func TestDeletingUserRevokesTheirAPITokens(t *testing.T) {
	ts, adminTok := newTestServer(t)
	_, body := tokenCall(t, ts, "POST", "/api/v1/users", adminTok, `{"username":"second","password":"second-password","role":"admin"}`)
	id := regexp.MustCompile(`"id":(\d+)`).FindStringSubmatch(body)[1]
	second := login(t, ts, "second", "second-password")
	_, body = tokenCall(t, ts, "POST", "/api/v1/api-tokens", second, `{"name":"leaver"}`)
	tok := regexp.MustCompile(`safe_ro_[0-9a-f]+`).FindString(body)
	if code, _ := tokenCall(t, ts, "GET", "/api/v1/stats", tok, ""); code != http.StatusOK {
		t.Fatalf("before delete: %d", code)
	}
	if code, _ := tokenCall(t, ts, "DELETE", "/api/v1/users/"+id, adminTok, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := tokenCall(t, ts, "GET", "/api/v1/stats", tok, ""); code != http.StatusUnauthorized {
		t.Errorf("after delete: %d, want 401", code)
	}
}
