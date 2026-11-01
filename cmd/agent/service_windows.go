//go:build windows

package main

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc"
)

const defaultStatePath = `C:\ProgramData\safe-agent\state.json`

// runAsService 在由服务控制管理器启动时接管运行，否则返回 handled=false。
func runAsService(run func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, err
	}
	return true, svc.Run("safe-agent", &service{run: run})
}

type service struct {
	run func(context.Context) error
}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel() // Agent 收到停止后会向管理中心发送最后一次上报（Agent 被停止）
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		case err := <-done:
			// 运行意外结束（例如无法连接管理中心）：以非零退出码结束，由服务的失败恢复策略重启
			if err != nil {
				slog.Error("agent stopped", "err", err)
			}
			return false, 1
		}
	}
}
