package agent

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"safe/internal/honeypot"
	"safe/internal/model"
	"safe/internal/simulate"
)

// 自检动作只做以下预定义的无害操作，产物都带自检编号并在结束后清理；不执行任何来自服务端的任意命令。
var (
	simCronDir  = "/etc/cron.d"
	simTmpDir   = "/tmp"
	simDuration = 120 * time.Second // 产物保留时长：覆盖 Agent 采集周期，保证能被检测到
)

func (a *Agent) runCommand(cmd model.AgentCommand) model.CommandResult {
	res := model.CommandResult{ID: cmd.ID, Status: "done"}
	if cmd.Type != "simulate" || !simulate.IDPattern.MatchString(cmd.ID) {
		res.Status, res.Detail = "error", "unsupported command"
		return res
	}
	var err error
	na := ""
	switch cmd.Scenario {
	case simulate.FileTamper:
		na, err = a.simFile(cmd.ID)
	case simulate.SuspiciousProcess:
		na, err = simProcess(cmd.ID)
	case simulate.HoneypotAccess:
		err = simHoneypot(cmd.ID, cmd.Params["target"])
	default:
		res.Status, res.Detail = "error", "unknown scenario "+cmd.Scenario
		return res
	}
	switch {
	case na != "":
		res.Status, res.Detail = "not_applicable", na
	case err != nil:
		res.Status, res.Detail = "error", err.Error()
	}
	slog.Info("attack simulation", "id", cmd.ID, "scenario", cmd.Scenario, "status", res.Status, "detail", res.Detail)
	return res
}

// simFile 在计划任务目录写入一个只含注释的文件（不会被执行），稍后删除。
func (a *Agent) simFile(id string) (string, error) {
	monitored := false
	for _, p := range a.cfg.FIMPaths {
		if filepath.Clean(p) == simCronDir {
			monitored = true
		}
	}
	if !monitored {
		return "文件完整性监控未包含 " + simCronDir, nil
	}
	path := filepath.Join(simCronDir, "safe-simulation-"+id)
	content := "# safe 攻击模拟自检 " + id + "：只含注释，不会执行，约 2 分钟后自动删除\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "无法写入 " + simCronDir + "（" + err.Error() + "）", nil
	}
	time.AfterFunc(simDuration, func() { os.Remove(path) })
	return "", nil
}

// SimulationChildArg 是"临时目录执行"自检启动测试进程用的参数：测试进程就是 Agent 自身的副本，
// 收到该参数后只等待指定秒数然后退出。不使用系统 sleep：uutils（Ubuntu 26.04 起）、BusyBox 等多合一程序
// 按文件名分派命令，复制改名后无法运行。
const SimulationChildArg = "-simulation-child-sleep"

// RunSimulationChildIfRequested 在 main 最开始调用：如果本进程是自检测试进程，等待后退出，不会返回。
func RunSimulationChildIfRequested() {
	if len(os.Args) == 3 && os.Args[1] == SimulationChildArg {
		secs, err := strconv.Atoi(os.Args[2])
		if err != nil || secs <= 0 || secs > 600 {
			os.Exit(2)
		}
		time.Sleep(time.Duration(secs) * time.Second)
		os.Exit(0)
	}
}

// simProcess 把 Agent 自身复制到临时目录运行（只等待，不做任何事），稍后结束并删除。
func simProcess(id string) (string, error) {
	if runtime.GOOS != "linux" {
		return "进程检测仅支持 Linux", nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dst := filepath.Join(simTmpDir, "safe-sim-"+id)
	if err := copyFile(self, dst, 0o700); err != nil {
		return "", err
	}
	cmd := exec.Command(dst, SimulationChildArg, strconv.Itoa(int(simDuration.Seconds())))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		os.Remove(dst)
		return simTmpDir + " 不允许执行程序（noexec 挂载？）", nil
	}
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		os.Remove(dst)
	}()
	// 确认进程确实在运行：立即退出的话自检必然失败，直接报告原因，而不是让它看起来像检测失效
	select {
	case err := <-exited:
		return "", fmt.Errorf("测试程序启动后立即退出（%v）：%s", err, strings.TrimSpace(stderr.String()))
	case <-time.After(500 * time.Millisecond):
		return "", nil
	}
}

// simHoneypot 连接蜜罐并发送自检标记。
func simHoneypot(id, target string) error {
	if target == "" {
		return fmt.Errorf("没有可用的蜜罐目标")
	}
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("连接蜜罐 %s 失败：%w", target, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s%s\n", honeypot.SimulationMarker, id); err != nil {
		return err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || strings.TrimSpace(reply) != "OK" {
		return fmt.Errorf("蜜罐 %s 未确认（%q %v）", target, reply, err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
