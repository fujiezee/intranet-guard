// safe-loadtest 模拟大量 Agent 压测管理中心：每个模拟 Agent 走真实的注册流程（独立私钥与证书、双向 TLS、
// 多实例故障切换），之后按上报周期发送按真实比例构造的事件。只用于测试环境。
//
//	SAFE_LOADTEST_PASSWORD=... safe-loadtest -console https://127.0.0.1 -nodes https://127.0.0.1:8443 -agents 10000
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"safe/internal/model"
	"safe/internal/node"
)

func main() {
	console := flag.String("console", "https://127.0.0.1", "management console URL (admin API)")
	user := flag.String("user", "admin", "admin username (password from SAFE_LOADTEST_PASSWORD)")
	nodes := flag.String("nodes", "https://127.0.0.1:8443", "node endpoint URLs, comma-separated for multiple instances")
	agents := flag.Int("agents", 1000, "number of simulated agents (at most 10000 per enrollment token)")
	interval := flag.Duration("interval", 30*time.Second, "report interval of each agent")
	duration := flag.Duration("duration", 5*time.Minute, "how long to report after all agents are enrolled")
	events := flag.Int("events", 30, "average events per report")
	alertEvery := flag.Int("alert-every", 0, "on average one in N reports carries a webshell event that raises one alert (0: off)")
	enrollConc := flag.Int("enroll-concurrency", 50, "parallel enrollments")
	dir := flag.String("dir", "", "directory for simulated agent certificates (default: temporary)")
	maxErr := flag.Float64("max-error-rate", 0.01, "fail if the error rate during the steady phase exceeds this")
	prefix := flag.String("id-prefix", fmt.Sprintf("load%04d", rand.IntN(10000)), "agent ID prefix (node IDs must be unique, so each run uses a new one)")
	maxP99 := flag.Duration("max-p99", 2*time.Second, "fail if p99 report latency exceeds this")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dir == "" {
		d, err := os.MkdirTemp("", "safe-loadtest-")
		if err != nil {
			fatal(err)
		}
		defer os.RemoveAll(d)
		*dir = d
	}

	token, err := enrollToken(ctx, *console, *user, os.Getenv("SAFE_LOADTEST_PASSWORD"), *agents)
	if err != nil {
		fatal(fmt.Errorf("create enrollment token: %w", err))
	}
	os.Setenv("SAFE_ENROLL_TOKEN", token)

	// 1. 注册
	start := time.Now()
	clients := make([]*node.Client, *agents)
	var enrolled, enrollFail atomic.Int64
	sem := make(chan struct{}, *enrollConc)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			id := fmt.Sprintf("%s-%05d", *prefix, i)
			c, err := node.Connect(ctx, string(model.NodeAgent), id, filepath.Join(*dir, id), *nodes)
			if err != nil {
				if enrollFail.Add(1) <= 3 {
					slog.Warn("enroll failed", "id", id, "err", err)
				}
				return
			}
			clients[i] = c
			if n := enrolled.Add(1); n%1000 == 0 {
				slog.Info("enrolling", "done", n, "elapsed", time.Since(start).Round(time.Second))
			}
		}(i)
	}
	wg.Wait()
	enrollTime := time.Since(start)
	slog.Info("enrollment finished", "enrolled", enrolled.Load(), "failed", enrollFail.Load(), "elapsed", enrollTime.Round(time.Millisecond),
		"rate_per_s", fmt.Sprintf("%.0f", float64(enrolled.Load())/enrollTime.Seconds()))
	if ctx.Err() != nil {
		return
	}

	// 2. 上报：各 Agent 在一个周期内均匀错开，模拟真实分布；第一个周期为预热，不计入结果
	st := &stats{}
	runCtx, cancel := context.WithTimeout(ctx, *interval+*duration)
	defer cancel()
	steadyAt := time.Now().Add(*interval)
	for i, c := range clients {
		if c == nil {
			continue
		}
		go reportLoop(runCtx, c, i, *interval, *events, *alertEvery, st, steadyAt)
	}
	go progress(runCtx, st, 10*time.Second)
	<-runCtx.Done()

	sum := st.summary(*duration)
	out, _ := json.MarshalIndent(map[string]any{
		"agents": enrolled.Load(), "enroll_failed": enrollFail.Load(), "enroll_seconds": enrollTime.Seconds(),
		"interval": interval.String(), "events_per_report": *events, "steady": sum, "alert_events_accepted": st.alerts.Load(),
	}, "", "  ")
	fmt.Println(string(out))
	switch {
	case enrollFail.Load() > 0:
		fatal(fmt.Errorf("%d agents failed to enroll", enrollFail.Load()))
	case sum.ErrorRate > *maxErr:
		fatal(fmt.Errorf("error rate %.4f exceeds %.4f", sum.ErrorRate, *maxErr))
	case time.Duration(sum.P99Ms*float64(time.Millisecond)) > *maxP99:
		fatal(fmt.Errorf("p99 latency %.0fms exceeds %s", sum.P99Ms, *maxP99))
	}
}

func fatal(err error) {
	slog.Error("load test failed", "err", err)
	os.Exit(1)
}

// enrollToken 以管理员身份登录控制台并创建足够次数的注册令牌。
func enrollToken(ctx context.Context, console, user, password string, n int) (string, error) {
	if password == "" {
		return "", errors.New("SAFE_LOADTEST_PASSWORD is not set")
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 测试环境的控制台常用自签名证书
	}}
	call := func(path, auth string, body, out any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, console+"/api/v1"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("%s: %s %s", path, resp.Status, msg)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var login struct{ Token string }
	if err := call("/auth/login", "", map[string]string{"username": user, "password": password}, &login); err != nil {
		return "", err
	}
	var tok struct{ Token string }
	err := call("/enroll-tokens", login.Token, map[string]any{"kind": "agent", "max_uses": n, "ttl_hours": 2, "note": "loadtest"}, &tok)
	return tok.Token, err
}

func reportLoop(ctx context.Context, c *node.Client, i int, interval time.Duration, avgEvents, alertEvery int, st *stats, steadyAt time.Time) {
	r := rand.New(rand.NewPCG(uint64(i), 42))
	info := model.AgentInfo{ID: c.ID, Hostname: c.ID, OS: "linux/amd64", Version: "loadtest",
		IPs: []string{fmt.Sprintf("10.%d.%d.%d", 100+i/65536, i/256%256, i%256)}, Capabilities: []string{"auth_log", "fim", "exec_monitor"}}
	select { // 均匀错开首次上报
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(r.Int64N(int64(interval)))):
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	url := c.Servers()[0].String() + "/api/v1/agent/report"
	for k := 1; ; k++ {
		alert := alertEvery > 0 && r.IntN(alertEvery) == 0
		body, n := report(r, info, avgEvents, alert, k)
		begin := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		ok := err == nil && resp.StatusCode < 300
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if ctx.Err() != nil {
			return // 测试结束时被取消的请求不计入
		}
		if begin.After(steadyAt) {
			st.record(time.Since(begin), n, ok)
		}
		if alert && ok {
			st.alerts.Add(1) // 服务端已接受、应产生一条告警
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// report 构造一次上报：约 90% 交互命令审计记录，其余为登录成功、sudo 和少量登录失败（会触发爆破检测查询）。
func report(r *rand.Rand, info model.AgentInfo, avg int, alert bool, k int) ([]byte, int) {
	n := 0
	if avg > 0 {
		n = r.IntN(2*avg + 1)
	}
	now := time.Now()
	events := make([]model.HostEvent, 0, n)
	for j := 0; j < n; j++ {
		ev := model.HostEvent{Time: now, User: "ops"}
		switch p := r.IntN(100); {
		case p < 90:
			ev.Type, ev.Detail = model.EventCommand, fmt.Sprintf("systemctl status app-%d（父进程 bash）", r.IntN(50))
		case p < 95:
			ev.Type, ev.SrcIP, ev.Detail = model.EventLoginSuccess, "10.9.0.10", "ssh publickey"
		case p < 98:
			ev.Type, ev.Detail = model.EventSudo, "COMMAND=/usr/bin/systemctl restart app"
		default:
			ev.Type, ev.SrcIP, ev.Detail = model.EventLoginFailed, fmt.Sprintf("10.9.%d.%d", r.IntN(4), r.IntN(250)), "ssh password"
		}
		events = append(events, ev)
	}
	if alert { // 每次路径不同：Webshell 告警不去重，每个事件对应一条告警
		events = append(events, model.HostEvent{Type: model.EventWebshell, Time: now, Severity: "high",
			Path: fmt.Sprintf("/var/www/html/upload/%s-%d.php", info.ID, k), Detail: "新增脚本文件，含 Webshell 特征：eval（压测）"})
	}
	b, _ := json.Marshal(model.AgentReport{Agent: info, Events: events})
	return b, n
}

type stats struct {
	alerts    atomic.Int64
	mu        sync.Mutex
	latencies []time.Duration
	events    int64
	errors    int64
	window    struct{ reqs, events, errors int64 }
}

func (s *stats) record(d time.Duration, events int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latencies = append(s.latencies, d)
	s.window.reqs++
	if ok {
		s.events += int64(events)
		s.window.events += int64(events)
	} else {
		s.errors++
		s.window.errors++
	}
}

type summary struct {
	Requests     int     `json:"requests"`
	ReqPerSec    float64 `json:"requests_per_second"`
	EventsPerSec float64 `json:"events_per_second"`
	ErrorRate    float64 `json:"error_rate"`
	P50Ms        float64 `json:"p50_ms"`
	P95Ms        float64 `json:"p95_ms"`
	P99Ms        float64 `json:"p99_ms"`
	MaxMs        float64 `json:"max_ms"`
}

func (s *stats) summary(d time.Duration) summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := slices.Clone(s.latencies)
	slices.Sort(l)
	pct := func(p float64) float64 {
		if len(l) == 0 {
			return 0
		}
		return float64(l[min(len(l)-1, int(p*float64(len(l))))]) / float64(time.Millisecond)
	}
	sum := summary{Requests: len(l), ReqPerSec: float64(len(l)) / d.Seconds(), EventsPerSec: float64(s.events) / d.Seconds(),
		P50Ms: pct(0.5), P95Ms: pct(0.95), P99Ms: pct(0.99), MaxMs: pct(1)}
	if len(l) > 0 {
		sum.ErrorRate = float64(s.errors) / float64(len(l))
	}
	return sum
}

func progress(ctx context.Context, s *stats, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		w := s.window
		s.window = struct{ reqs, events, errors int64 }{}
		var recent []time.Duration
		if n := len(s.latencies); n > 0 {
			recent = slices.Clone(s.latencies[max(0, n-int(w.reqs)):])
		}
		s.mu.Unlock()
		slices.Sort(recent)
		p99 := time.Duration(0)
		if len(recent) > 0 {
			p99 = recent[min(len(recent)-1, len(recent)*99/100)]
		}
		slog.Info("progress", "req_per_s", fmt.Sprintf("%.0f", float64(w.reqs)/every.Seconds()),
			"events_per_s", fmt.Sprintf("%.0f", float64(w.events)/every.Seconds()), "errors", w.errors, "p99", p99.Round(time.Millisecond))
	}
}
