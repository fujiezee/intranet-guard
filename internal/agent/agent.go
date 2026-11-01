// Package agent 实现主机 Agent：采集登录 / sudo 日志、文件完整性、可疑进程，定期上报管理中心。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"safe/internal/model"
	"safe/internal/tail"
)

const Version = "0.3.0"

// AuthLogCandidates 按顺序尝试的认证日志文件（Debian/Ubuntu、RHEL/CentOS）；都不存在时使用 journald。
var AuthLogCandidates = []string{"/var/log/auth.log", "/var/log/secure"}

type Config struct {
	ServerURL string
	HTTP      *http.Client // mTLS 客户端（见 internal/node）
	Token     string       // 旧版共享 token，仅在未注册证书时使用
	AgentID   string
	StatePath string
	Interval  time.Duration
	FIMPaths  []string
}

// State 持久化到磁盘，Agent 重启后从上次位置继续，不重复上报也不漏报。
type State struct {
	AuthFile      *tail.State         `json:"auth_file,omitempty"`
	JournalCursor string              `json:"journal_cursor,omitempty"`
	Files         map[string]FileInfo `json:"files,omitempty"`
	Processes     map[string]bool     `json:"processes,omitempty"`
}

type Agent struct {
	cfg   Config
	info  model.AgentInfo
	state State
	http  *http.Client
}

func New(cfg Config) (*Agent, error) {
	hostname, _ := os.Hostname()
	if cfg.AgentID == "" {
		cfg.AgentID = hostname
	}
	a := &Agent{
		cfg:  cfg,
		info: model.AgentInfo{ID: cfg.AgentID, Hostname: hostname, OS: runtime.GOOS + "/" + runtime.GOARCH, Version: Version},
		http: cfg.HTTP,
	}
	if a.http == nil {
		a.http = &http.Client{Timeout: 30 * time.Second}
	}
	if err := a.loadState(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Agent) Run(ctx context.Context) {
	slog.Info("safe-agent started", "id", a.cfg.AgentID, "server", a.cfg.ServerURL, "version", Version)
	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		a.cycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cycle 采集一轮事件并上报；只有上报成功才提交新状态，失败时下一轮重新采集同一批数据。
func (a *Agent) cycle(ctx context.Context) {
	now := time.Now()
	next := a.state
	var events []model.HostEvent

	ev, err := a.collectAuth(ctx, &next, now)
	if err != nil {
		slog.Warn("collect auth log", "err", err)
	}
	events = append(events, ev...)

	files := ScanFiles(a.cfg.FIMPaths)
	if a.state.Files != nil { // 首次运行只建立基线
		events = append(events, DiffFiles(a.state.Files, files, now)...)
	}
	next.Files = files

	next.Processes = map[string]bool{}
	for key, ev := range ScanProcesses(now) {
		if !a.state.Processes[key] {
			events = append(events, ev)
		}
		next.Processes[key] = true
	}

	a.info.IPs = localIPs()
	if events == nil {
		events = []model.HostEvent{}
	}
	if err := a.send(ctx, model.AgentReport{Agent: a.info, Events: events}); err != nil {
		slog.Warn("report failed, will retry", "events", len(events), "err", err)
		return
	}
	a.state = next
	if err := a.saveState(); err != nil {
		slog.Error("save state", "err", err)
	}
	if len(events) > 0 {
		slog.Info("reported events", "count", len(events))
	}
}

func (a *Agent) collectAuth(ctx context.Context, next *State, now time.Time) ([]model.HostEvent, error) {
	for _, path := range AuthLogCandidates {
		if _, err := os.Stat(path); err == nil {
			ev, st, err := ReadAuthFile(path, a.state.AuthFile, now)
			next.AuthFile = st
			return ev, err
		}
	}
	ev, cursor, err := ReadJournal(ctx, a.state.JournalCursor, now)
	next.JournalCursor = cursor
	return ev, err
}

func (a *Agent) send(ctx context.Context, rep model.AgentReport) error {
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.ServerURL+"/api/v1/agent/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	return nil
}

func (a *Agent) loadState() error {
	data, err := os.ReadFile(a.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return json.Unmarshal(data, &a.state)
}

func (a *Agent) saveState() error {
	data, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.StatePath), 0o700); err != nil {
		return err
	}
	tmp := a.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfg.StatePath)
}

// localIPs 返回本机非回环 IPv4 地址，管理中心用它把主机事件关联到资产。
func localIPs() []string {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipn, ok := addr.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			ips = append(ips, ipn.IP.String())
		}
	}
	return ips
}
