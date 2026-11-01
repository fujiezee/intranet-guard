package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheck(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("GitHub API requires a User-Agent")
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c := New(srv.URL, "0.9.0")
	status, body = 200, `{"tag_name":"v0.10.0","html_url":"https://example/r","body":"新功能","published_at":"2026-11-02T00:00:00Z"}`
	c.Check(context.Background())
	if s := c.Status(); !s.UpdateAvailable || s.Latest != "0.10.0" || s.ReleaseNotes != "新功能" || s.CheckedAt == nil {
		t.Errorf("new release: %+v", s)
	}
	status, body = 200, `{"tag_name":"v0.9.0"}`
	c.Check(context.Background())
	if s := c.Status(); s.UpdateAvailable {
		t.Errorf("same version: %+v", s)
	}
	status, body = 404, `{}` // 还没有发布
	c.Check(context.Background())
	if s := c.Status(); s.UpdateAvailable || s.CheckError != "" {
		t.Errorf("no release: %+v", s)
	}
	srv.Close() // 内网无法访问
	c.Check(context.Background())
	if s := c.Status(); s.UpdateAvailable || s.CheckError == "" || s.Current != "0.9.0" {
		t.Errorf("unreachable: %+v", s)
	}
	if s := New("", "0.9.0").Status(); !s.Disabled {
		t.Error("empty URL should disable checking")
	}
}
