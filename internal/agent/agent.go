// Package agent 实现主机 Agent：采集登录 / sudo 日志、文件完整性、可疑进程，定期上报管理中心。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"safe/internal/model"
	"safe/internal/tail"
)

// Version 由 make release 通过 -ldflags "-X safe/internal/agent.Version=…" 写入；直接 go build 时为 dev。
var Version = "dev"

// AuthLogCandidates 按顺序尝试的认证日志文件（Debian/Ubuntu、RHEL/CentOS）；都不存在时使用 journald。
var AuthLogCandidates = []string{"/var/log/auth.log", "/var/log/secure"}

type Config struct {
	ServerURL  string       // 请求按第一个实例拼 URL，连接失败时由 node 包切换到其他实例
	ServerURLs []string     // 全部管理中心实例（隔离主机时都要放行）
	HTTP       *http.Client // mTLS 客户端（见 internal/node）
	Token      string       // 旧版共享 token，仅在未注册证书时使用
	AgentID    string
	StatePath  string
	Interval   time.Duration
	FIMPaths   []string
	WebDirs    []string // Webshell 监控的网站目录
}

// State 持久化到磁盘，Agent 重启后从上次位置继续，不重复上报也不漏报。
type State struct {
	AuthFile      *tail.State         `json:"auth_file,omitempty"`
	JournalCursor string              `json:"journal_cursor,omitempty"`
	Files         map[string]FileInfo `json:"files,omitempty"`
	Processes     map[string]bool     `json:"processes,omitempty"`
	WebFiles      map[string]FileInfo `json:"web_files,omitempty"`
	WinBookmarks  map[string]uint64   `json:"win_bookmarks,omitempty"` // Windows 事件日志读取位置（EventRecordID）
}

type Agent struct {
	cfg     Config
	info    model.AgentInfo
	state   State
	http    *http.Client
	results []model.CommandResult // 指令执行结果，随下一次上报带回

	pendingUpgrade   *pendingUpgrade // 刚升级到本版本、尚未确认（首次上报成功后确认）
	restartRequested bool            // 已安装新版本，回报结果后退出以重启

	execMu      sync.Mutex
	execEvents  []model.HostEvent    // 进程监控产生、尚未上报的事件
	execDropped int                  // 缓冲区满时丢弃的数量
	execSeen    map[string]time.Time // 相同规则 + 命令 60 秒内只上报一次

	win          winDetector       // Windows 事件检测
	winBookmarks map[string]uint64 // 已处理到的事件日志位置，保存状态时写入 State
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
	a.loadUpgradeState()
	monCtx, stopMon := context.WithCancel(context.Background())
	defer stopMon()
	switch runtime.GOOS {
	case "windows":
		// 命令审计来自安全日志 4688，见到第一条进程创建事件后才加上 exec_monitor（见 collectWinlog）
		a.info.Capabilities = []string{"winlog", "fim", "webshell"}
		a.winBookmarks = map[string]uint64{}
		for k, v := range a.state.WinBookmarks {
			a.winBookmarks[k] = v
		}
	default:
		a.info.Capabilities = []string{"auth_log", "fim", "webshell"}
		if runtime.GOOS == "linux" {
			a.info.Capabilities = append(a.info.Capabilities, "process_scan")
		}
		if err := startProcMonitor(monCtx, a.onExec); err != nil {
			slog.Warn("command auditing disabled", "err", err)
		} else {
			a.info.Capabilities = append(a.info.Capabilities, "exec_monitor")
			slog.Info("command auditing enabled (proc connector)")
		}
	}

	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		a.cycle(ctx)
		select {
		case <-ctx.Done():
			a.notifyStopping()
			return
		case <-t.C:
		}
	}
}

// notifyStopping 在收到停止信号（systemctl stop、关机）时告知管理中心，与"失联"区分开。
func (a *Agent) notifyStopping() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info := a.info
	info.Stopping = true
	if _, err := a.send(ctx, model.AgentReport{Agent: info, Events: a.takeExecEvents(), Results: a.results}); err != nil {
		slog.Warn("notify stopping", "err", err)
	}
}

const maxExecBuffer = 5000

// onExec 处理进程监控推送的每次执行：命中规则的上报为可疑命令，交互式终端中的命令作为审计记录。
func (a *Agent) onExec(e ExecInfo) {
	findings := EvaluateExec(e)
	if len(findings) == 0 && !e.TTY {
		return
	}
	now := time.Now()
	var events []model.HostEvent
	where := ""
	if c := e.Container.String(); c != "" {
		where = "；位置：" + c
	}
	for _, f := range findings {
		detail := fmt.Sprintf("[%s] %s；命令：%s；父进程：%s%s", f.Name, f.Reason, e.Cmdline, e.ParentComm, where)
		events = append(events, model.HostEvent{Type: model.EventSuspiciousCommand, Time: now, User: e.User,
			SrcIP: hostOf(e.StdioRemote), Path: e.Exe, Detail: detail, Severity: f.Severity})
	}
	if len(findings) == 0 {
		events = append(events, model.HostEvent{Type: model.EventCommand, Time: now, User: e.User, Path: e.Exe,
			Detail: e.Cmdline + "（父进程 " + e.ParentComm + "）" + where})
	}

	a.execMu.Lock()
	defer a.execMu.Unlock()
	if a.execSeen == nil || len(a.execSeen) > 10000 {
		a.execSeen = map[string]time.Time{}
	}
	for _, ev := range events {
		key := string(ev.Type) + "|" + ev.Detail
		if t, ok := a.execSeen[key]; ok && now.Sub(t) < time.Minute {
			continue // 循环脚本反复执行同一命令时只报一次
		}
		a.execSeen[key] = now
		if len(a.execEvents) >= maxExecBuffer {
			a.execDropped++
			continue
		}
		a.execEvents = append(a.execEvents, ev)
	}
}

func (a *Agent) takeExecEvents() []model.HostEvent {
	a.execMu.Lock()
	defer a.execMu.Unlock()
	ev := a.execEvents
	a.execEvents = nil
	if a.execDropped > 0 {
		ev = append(ev, model.HostEvent{Type: model.EventCommand, Time: time.Now(),
			Detail: fmt.Sprintf("命令审计缓冲区已满，丢弃 %d 条记录（上报不畅或命令执行过于频繁）", a.execDropped)})
		a.execDropped = 0
	}
	return ev
}

// putBackExecEvents 在上报失败时把事件放回缓冲区，下次重试。
func (a *Agent) putBackExecEvents(ev []model.HostEvent) {
	a.execMu.Lock()
	defer a.execMu.Unlock()
	a.execEvents = append(ev, a.execEvents...)
	if over := len(a.execEvents) - maxExecBuffer; over > 0 {
		a.execEvents = a.execEvents[over:]
		a.execDropped += over
	}
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return ""
}

// cycle 采集一轮事件并上报；只有上报成功才提交新状态，失败时下一轮重新采集同一批数据。
func (a *Agent) cycle(ctx context.Context) {
	now := time.Now()
	next := a.state
	var events []model.HostEvent

	if runtime.GOOS == "windows" {
		a.putBackExecEvents(a.collectWinlog()) // 与命令审计事件共用缓冲区：上报失败时保留重试
		a.sweepWinBlocks()
	} else {
		ev, err := a.collectAuth(ctx, &next, now)
		if err != nil {
			slog.Warn("collect auth log", "err", err)
		}
		events = append(events, ev...)
	}

	files := ScanFiles(a.cfg.FIMPaths)
	if a.state.Files != nil { // 首次运行只建立基线
		events = append(events, DiffFiles(a.state.Files, files, now)...)
	}
	next.Files = files

	webFiles := scanWebDirs(a.cfg.WebDirs)
	if a.state.WebFiles != nil { // 首次运行只建立基线
		events = append(events, diffWebFiles(a.state.WebFiles, webFiles, now)...)
	}
	next.WebFiles = webFiles

	next.Processes = map[string]bool{}
	for key, ev := range ScanProcesses(now) {
		if !a.state.Processes[key] {
			events = append(events, ev)
		}
		next.Processes[key] = true
	}

	execEvents := a.takeExecEvents()
	events = append(events, execEvents...)

	a.info.IPs = localIPs()
	if events == nil {
		events = []model.HostEvent{}
	}
	cmds, err := a.send(ctx, model.AgentReport{Agent: a.info, Events: events, Results: a.results})
	if err != nil {
		slog.Warn("report failed, will retry", "events", len(events), "err", err)
		a.putBackExecEvents(execEvents)
		return
	}
	a.results = nil
	a.commitUpgrade()
	a.runCommands(ctx, cmds)
	if a.winBookmarks != nil {
		next.WinBookmarks = map[string]uint64{}
		for k, v := range a.winBookmarks {
			next.WinBookmarks[k] = v
		}
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

// send 上报并返回管理中心下发的指令。
func (a *Agent) send(ctx context.Context, rep model.AgentReport) ([]model.AgentCommand, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.ServerURL+"/api/v1/agent/report", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	var out model.AgentReportResponse
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) // 旧版管理中心返回 204，无指令
	}
	return out.Commands, nil
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

// runCommands 执行指令后立即回报结果（不等下一个采集周期），处置和自检的结果能尽快出现在控制台。
// 回报的回复里可能还有新指令，最多连续处理几轮。
func (a *Agent) runCommands(ctx context.Context, cmds []model.AgentCommand) {
	defer func() {
		if a.restartRequested {
			// 结果已回报（或回报失败：新版本上线后管理中心按版本号确认）。退出后由服务管理器以新版本重启
			slog.Info("exiting to restart as the upgraded version")
			os.Exit(RestartExitCode)
		}
	}()
	for round := 0; round < 3 && len(cmds) > 0; round++ {
		for _, c := range cmds {
			a.results = append(a.results, a.runCommand(c))
		}
		next, err := a.send(ctx, model.AgentReport{Agent: a.info, Events: []model.HostEvent{}, Results: a.results})
		if err != nil {
			return // 结果留到下一个周期随常规上报带回
		}
		a.results = nil
		cmds = next
	}
	for _, c := range cmds {
		a.results = append(a.results, a.runCommand(c))
	}
}
