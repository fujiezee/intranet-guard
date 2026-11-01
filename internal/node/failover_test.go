package node

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestFailover(t *testing.T) {
	// A：已停止的实例（端口无人监听）
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()

	var hits atomic.Int32
	var status atomic.Int32
	status.Store(200)
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(int(status.Load()))
		w.Write(body)
	}))
	defer b.Close()

	ua, _ := url.Parse(dead)
	ub, _ := url.Parse(b.URL)
	f := &failover{base: http.DefaultTransport, servers: []*url.URL{ua, ub}}
	hc := &http.Client{Transport: f}

	// 请求按第一个地址拼 URL；A 连不上，换到 B，请求体完整重发
	resp, err := hc.Post(dead+"/api/v1/agent/report", "application/json", bytes.NewReader([]byte(`{"x":1}`)))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != `{"x":1}` || f.cur.Load() != 1 {
		t.Fatalf("failover: body=%q cur=%d", got, f.cur.Load())
	}
	// 记住可用实例：之后直接发往 B
	hc.Get(dead + "/x")
	if hits.Load() != 2 {
		t.Errorf("hits = %d", hits.Load())
	}
	// HTTP 错误状态码是实例的明确答复，不切换
	status.Store(500)
	resp, err = hc.Get(dead + "/x")
	if err != nil || resp.StatusCode != 500 || f.cur.Load() != 1 {
		t.Errorf("5xx handling: %v %v cur=%d", resp, err, f.cur.Load())
	}
	// 全部实例都不可用时返回错误
	b.Close()
	if _, err := hc.Get(dead + "/x"); err == nil {
		t.Error("expected error when all instances are down")
	}
	// 发往其他主机的请求不受影响
	if _, err := ParseServers("https://a:8443, https://b:8443/ ,"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "http://a:8443", "https://"} {
		if _, err := ParseServers(bad); err == nil {
			t.Errorf("ParseServers(%q) accepted", bad)
		}
	}
}
