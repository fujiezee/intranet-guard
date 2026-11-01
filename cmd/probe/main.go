// safe-probe 部署在各个网段，定期向管理中心领取扫描任务并上报结果。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"safe/internal/honeypot"
	"safe/internal/ids"
	"safe/internal/model"
	"safe/internal/node"
	"safe/internal/scanner"
	"safe/internal/tail"
	"safe/internal/vuln"
)

type client struct {
	base    string
	token   string
	probeID string
	http    *http.Client
}

func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, &buf)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func main() {
	serverURL := flag.String("server", "https://127.0.0.1:8443", "management server node endpoint URL")
	probeID := flag.String("id", "", "probe ID, e.g. the segment name (required for enrollment)")
	interval := flag.Duration("interval", 10*time.Second, "task polling interval")
	concurrency := flag.Int("concurrency", 512, "concurrent TCP connections")
	timeout := flag.Duration("timeout", time.Second, "per-connection timeout")
	evePath := flag.String("eve", "", "Suricata eve.json path; enables traffic IDS reporting")
	statePath := flag.String("state", "/var/lib/safe-probe/state.json", "state file; certificates are kept in the same directory")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := &client{base: strings.TrimRight(*serverURL, "/"), probeID: *probeID}
	nc, err := node.Connect(ctx, string(model.NodeProbe), *probeID, filepath.Dir(*statePath), *serverURL)
	switch {
	case err == nil:
		c.http, c.probeID = nc.HTTP, nc.ID
		go nc.RenewLoop(ctx)
	case errors.Is(err, node.ErrNotEnrolled) && os.Getenv("SAFE_PROBE_TOKEN") != "" && *probeID != "":
		slog.Warn("using legacy shared token; enroll with SAFE_ENROLL_TOKEN for certificate authentication")
		c.token, c.http = os.Getenv("SAFE_PROBE_TOKEN"), &http.Client{Timeout: 60 * time.Second}
	default:
		slog.Error("connect to management server", "err", err)
		os.Exit(1)
	}
	opts := scanner.Options{Concurrency: *concurrency, Timeout: *timeout}

	if *evePath != "" {
		go runEve(ctx, c, *evePath, *statePath)
	}
	go runHoneypot(ctx, c)

	slog.Info("safe-probe started", "id", c.probeID, "server", *serverURL, "eve", *evePath)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		var tasks []model.ScanTask
		if err := c.do(ctx, http.MethodGet, "/api/v1/probe/tasks?probe_id="+url.QueryEscape(c.probeID), nil, &tasks); err != nil {
			slog.Warn("poll tasks", "err", err)
		}
		for _, t := range tasks {
			runTask(ctx, c, t, opts)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runTask(ctx context.Context, c *client, t model.ScanTask, opts scanner.Options) {
	rep := model.ScanReport{TaskID: t.ID, ProbeID: c.probeID, StartedAt: time.Now().UTC(), Assets: []model.Asset{}}
	slog.Info("task started", "task", t.ID, "kind", t.Kind, "targets", t.Targets, "ports", len(t.Ports))

	targets, err := scanner.ExpandTargets(t.Targets)
	if err != nil {
		rep.Error = err.Error()
	} else {
		opts.Ports = t.Ports
		rep.Assets = scanner.Scan(ctx, targets, opts)
		if t.Kind == model.TaskVuln {
			rep.Checks = vuln.Run(ctx, rep.Assets, vuln.Options{WeakPassword: t.WeakPassword})
		}
	}
	if ctx.Err() != nil {
		// 结果不完整，不能用来判断端口关闭，丢弃。
		rep.Error = "probe stopped before scan completed"
		rep.Assets, rep.Checks = []model.Asset{}, nil
	}
	rep.FinishedAt = time.Now().UTC()

	// 用独立的 context 上报，保证探针退出时也能把失败状态告诉管理中心。
	sendCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.do(sendCtx, http.MethodPost, "/api/v1/probe/reports", rep, nil); err != nil {
		slog.Error("submit report", "task", t.ID, "err", err)
		return
	}
	found := 0
	for _, c := range rep.Checks {
		if c.Vulnerable {
			found++
		}
	}
	slog.Info("task finished", "task", t.ID, "assets", len(rep.Assets), "vulns", found, "dur", rep.FinishedAt.Sub(rep.StartedAt))
}

const eveInterval = 5 * time.Second

// runEve 持续读取 Suricata 的 eve.json，把告警上报管理中心。
// 上报成功后才保存读取位置，管理中心不可达时下次从同一位置重试。
func runEve(ctx context.Context, c *client, path, statePath string) {
	state := loadTailState(statePath)
	t := time.NewTicker(eveInterval)
	defer t.Stop()
	for {
		// 一轮内循环读取直到追上文件末尾。
		for {
			lines, next, err := tail.ReadLines(path, state)
			if err != nil {
				slog.Warn("read eve.json", "path", path, "err", err)
				break
			}
			events := []model.IDSEvent{}
			for _, line := range lines {
				if ev, ok := ids.ParseEveLine(line); ok {
					events = append(events, ev)
				}
			}
			if len(events) > 0 {
				err := c.do(ctx, http.MethodPost, "/api/v1/probe/ids-events", model.IDSReport{ProbeID: c.probeID, Events: events}, nil)
				if err != nil {
					slog.Warn("submit IDS events, will retry", "events", len(events), "err", err)
					break
				}
				slog.Info("IDS events reported", "count", len(events))
			}
			advanced := state == nil || *next != *state
			state = next
			saveTailState(statePath, state)
			if len(lines) == 0 || !advanced {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func loadTailState(path string) *tail.State {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st tail.State
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	return &st
}

func saveTailState(path string, st *tail.State) {
	data, _ := json.Marshal(st)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		slog.Error("save state", "err", err)
		return
	}
	err := os.WriteFile(path+".tmp", data, 0o600)
	if err == nil {
		err = os.Rename(path+".tmp", path)
	}
	if err != nil {
		slog.Error("save state", "err", err)
	}
}

// runHoneypot 按管理中心下发的配置运行蜜罐，并定期上报访问事件。上报失败时事件留在内存中重试（最多 10000 条）。
func runHoneypot(ctx context.Context, c *client) {
	var mu sync.Mutex
	var pending []model.HoneypotEvent
	m := honeypot.New(func(ev model.HoneypotEvent) {
		mu.Lock()
		defer mu.Unlock()
		if len(pending) < 10000 {
			pending = append(pending, ev)
		}
		slog.Warn("honeypot accessed", "service", ev.Service, "port", ev.Port, "src", ev.SrcIP, "user", ev.Username)
	})
	fetch := func(ctx context.Context, status map[int]string) (model.HoneypotConfig, error) {
		var resp struct {
			Honeypot model.HoneypotConfig `json:"honeypot"`
		}
		err := c.do(ctx, http.MethodPost, "/api/v1/probe/config?probe_id="+url.QueryEscape(c.probeID),
			map[string]any{"ips": localIPs(), "status": status}, &resp)
		return resp.Honeypot, err
	}
	go honeypot.Run(ctx, m, fetch, 15*time.Second)

	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		mu.Lock()
		batch := pending
		pending = nil
		mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		if err := c.do(ctx, http.MethodPost, "/api/v1/probe/honeypot-events",
			map[string]any{"probe_id": c.probeID, "events": batch}, nil); err != nil {
			slog.Warn("submit honeypot events, will retry", "events", len(batch), "err", err)
			mu.Lock()
			pending = append(batch, pending...)
			mu.Unlock()
		}
	}
}

// localIPs 返回本机地址，管理中心据此在资产中标识蜜罐、为自检选择目标。
func localIPs() []string {
	ips := []string{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			ips = append(ips, ipn.IP.String())
		}
	}
	return ips
}
