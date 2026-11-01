// safe-agent 部署在每台服务器上，采集主机安全事件并上报管理中心。需要 root 权限运行。
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"safe/internal/agent"
	"safe/internal/model"
	"safe/internal/node"
)

func main() {
	agent.RunSimulationChildIfRequested()
	serverURL := flag.String("server", "https://127.0.0.1:8443", "management server node endpoint URL")
	id := flag.String("id", "", "agent ID (default: hostname)")
	statePath := flag.String("state", "/var/lib/safe-agent/state.json", "state file path")
	interval := flag.Duration("interval", 30*time.Second, "collect and report interval")
	fimPaths := flag.String("fim-paths", "", "comma-separated paths to monitor (default: built-in list)")
	authLog := flag.String("auth-log", "", "auth log file (default: /var/log/auth.log or /var/log/secure, else journald)")
	flag.Parse()

	if os.Geteuid() != 0 {
		slog.Warn("not running as root: auth logs, /etc/shadow and other users' processes may be unreadable")
	}

	paths := agent.DefaultFIMPaths
	if *fimPaths != "" {
		paths = strings.Split(*fimPaths, ",")
	}

	if *authLog != "" {
		agent.AuthLogCandidates = []string{*authLog}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := agent.Config{
		ServerURL: strings.TrimRight(*serverURL, "/"), AgentID: *id,
		StatePath: *statePath, Interval: *interval, FIMPaths: paths,
	}
	if cfg.AgentID == "" {
		cfg.AgentID, _ = os.Hostname()
	}
	nc, err := node.Connect(ctx, string(model.NodeAgent), cfg.AgentID, filepath.Dir(*statePath), *serverURL)
	switch {
	case err == nil:
		cfg.HTTP, cfg.AgentID = nc.HTTP, nc.ID
		go nc.RenewLoop(ctx)
	case errors.Is(err, node.ErrNotEnrolled) && os.Getenv("SAFE_AGENT_TOKEN") != "":
		slog.Warn("using legacy shared token; enroll with SAFE_ENROLL_TOKEN for certificate authentication")
		cfg.Token = os.Getenv("SAFE_AGENT_TOKEN")
	default:
		slog.Error("connect to management server", "err", err)
		os.Exit(1)
	}

	a, err := agent.New(cfg)
	if err != nil {
		slog.Error("init agent", "err", err)
		os.Exit(1)
	}
	a.Run(ctx)
}
