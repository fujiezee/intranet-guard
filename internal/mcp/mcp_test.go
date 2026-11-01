package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// run 发送一组请求，返回各响应（通知没有响应）。
func run(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Run(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		resps = append(resps, m)
	}
	return resps
}

func text(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	r, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	return r["content"].([]any)[0].(map[string]any)["text"].(string), r["isError"].(bool)
}

func TestProtocol(t *testing.T) {
	var requests []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		if strings.HasPrefix(r.URL.Path, "/api/v1/incidents/") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"incident not found"}`))
			return
		}
		if r.URL.Path == "/api/v1/assets" {
			w.Write([]byte(strings.Repeat("中", maxResult)))
			return
		}
		w.Write([]byte(`[{"id":1}]`))
	}))
	defer ts.Close()
	s := &Server{BaseURL: ts.URL, Token: "tok", HTTP: ts.Client()}

	resps := run(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_alerts","arguments":{"status":"open","limit":20}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_incident","arguments":{"id":"a/b"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_incident","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_assets"}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_everything"}}`,
		`{"jsonrpc":"2.0","id":8,"method":"nope"}`,
		`not json`,
	)
	if len(resps) != 9 {
		t.Fatalf("got %d responses: %v", len(resps), resps)
	}
	if r := resps[0]["result"].(map[string]any); r["protocolVersion"] != "2025-03-26" {
		t.Errorf("initialize: %v", r)
	}
	if defs := resps[1]["result"].(map[string]any)["tools"].([]any); len(defs) != len(tools) {
		t.Errorf("tools/list: %d", len(defs))
	}
	if got, isErr := text(t, resps[2]); isErr || got != `[{"id":1}]` {
		t.Errorf("list_alerts: %q %v", got, isErr)
	}
	if got, isErr := text(t, resps[3]); !isErr || !strings.Contains(got, "incident not found") {
		t.Errorf("not found: %q %v", got, isErr)
	}
	if got, isErr := text(t, resps[4]); !isErr || !strings.Contains(got, "id is required") {
		t.Errorf("missing id: %q %v", got, isErr)
	}
	if got, _ := text(t, resps[5]); len(got) > maxResult+100 || !strings.HasSuffix(got, "smaller limit]") || !json.Valid([]byte(`"`+got[:30]+`"`)) {
		t.Errorf("truncation: len %d", len(got))
	}
	for i := 6; i < 9; i++ {
		if resps[i]["error"] == nil {
			t.Errorf("response %d should be an error: %v", i, resps[i])
		}
	}
	want := []string{"GET /api/v1/alerts?limit=20&status=open Bearer tok", "GET /api/v1/incidents/a%2Fb Bearer tok", "GET /api/v1/assets Bearer tok"}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s", strings.Join(requests, "\n"))
	}
}

// 工具表只能指向查询接口：写操作在这里出现就是回归。
func TestToolsAreReadOnly(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range tools {
		if seen[tl.Name] || !strings.HasPrefix(tl.Path, "/") || strings.Contains(tl.Path, "api-tokens") {
			t.Errorf("bad tool %s", tl.Name)
		}
		seen[tl.Name] = true
	}
}
