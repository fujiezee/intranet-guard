// safe-agent 部署在每台服务器上，采集主机安全事件并上报管理中心。
// Linux 上需要 root；Windows 上作为服务以 LocalSystem 运行。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"safe/internal/agent"
	"safe/internal/model"
	"safe/internal/node"
)

func main() {
	agent.RunSimulationChildIfRequested()
	serverURL := flag.String("server", "https://127.0.0.1:8443", "management server node endpoint URL; comma-separated for multiple instances (automatic failover)")
	id := flag.String("id", "", "agent ID (default: hostname)")
	statePath := flag.String("state", defaultStatePath, "state file path")
	interval := flag.Duration("interval", 30*time.Second, "collect and report interval")
	fimPaths := flag.String("fim-paths", "", "comma-separated paths to monitor (default: built-in list)")
	webDirs := flag.String("web-dirs", strings.Join(agent.DefaultWebDirs, ","), "comma-separated web roots to watch for webshells (empty to disable)")
	authLog := flag.String("auth-log", "", "auth log file (default: /var/log/auth.log or /var/log/secure, else journald)")
	enrollOnly := flag.Bool("enroll-only", false, "enroll with SAFE_ENROLL_TOKEN (if not enrolled yet) and exit; used by the installer")
	logFile := flag.String("log-file", "", "write logs to this file instead of stderr (used when running as a Windows service)")
	flag.Parse()

	if *logFile != "" {
		f, err := openLog(*logFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open log file:", err)
			os.Exit(1)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(f, nil)))
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		slog.Warn("not running as root: auth logs, /etc/shadow and other users' processes may be unreadable")
	}

	paths := agent.DefaultFIMPaths
	if *fimPaths != "" {
		paths = strings.Split(*fimPaths, ",")
	}
	if *authLog != "" {
		agent.AuthLogCandidates = []string{*authLog}
	}
	servers, err := node.ParseServers(*serverURL)
	if err != nil {
		slog.Error("invalid -server", "err", err)
		os.Exit(2)
	}
	var serverList []string
	for _, u := range servers {
		serverList = append(serverList, u.String())
	}
	cfg := agent.Config{
		ServerURL: serverList[0], ServerURLs: serverList, AgentID: *id,
		StatePath: *statePath, Interval: *interval, FIMPaths: paths,
	}
	if *webDirs != "" {
		cfg.WebDirs = strings.Split(*webDirs, ",")
	}
	if cfg.AgentID == "" {
		cfg.AgentID, _ = os.Hostname()
	}

	run := func(ctx context.Context) error {
		nc, err := node.Connect(ctx, string(model.NodeAgent), cfg.AgentID, filepath.Dir(*statePath), *serverURL)
		switch {
		case err == nil && *enrollOnly:
			slog.Info("enrolled", "id", nc.ID)
			return nil
		case err == nil:
			cfg.HTTP, cfg.AgentID = nc.HTTP, nc.ID
			go nc.RenewLoop(ctx)
		case errors.Is(err, node.ErrNotEnrolled) && os.Getenv("SAFE_AGENT_TOKEN") != "" && !*enrollOnly:
			slog.Warn("using legacy shared token; enroll with SAFE_ENROLL_TOKEN for certificate authentication")
			cfg.Token = os.Getenv("SAFE_AGENT_TOKEN")
		default:
			return fmt.Errorf("connect to management server: %w", err)
		}
		a, err := agent.New(cfg)
		if err != nil {
			return fmt.Errorf("init agent: %w", err)
		}
		a.Run(ctx)
		return nil
	}

	// 作为 Windows 服务启动时由服务控制管理器驱动，停止服务等同于收到停止信号
	if handled, err := runAsService(run); handled {
		if err != nil {
			slog.Error("service", "err", err)
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

const maxLogSize = 50 << 20

// openLog 以追加方式打开日志文件；超过 50MB 时先改名为 .1 保留一份旧日志。
func openLog(path string) (io.Writer, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
