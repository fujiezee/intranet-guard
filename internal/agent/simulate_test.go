package agent

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
)

func TestSimulations(t *testing.T) {
	dir := t.TempDir()
	simCronDir = dir
	simDuration = 300 * time.Millisecond
	t.Cleanup(func() { simCronDir, simDuration = "/etc/cron.d", 120*time.Second })

	a := &Agent{cfg: Config{FIMPaths: []string{dir}}}
	res := a.runCommand(model.AgentCommand{ID: "sim-0000abcd", Type: "simulate", Scenario: "fim"})
	file := filepath.Join(dir, "safe-simulation-sim-0000abcd")
	if res.Status != "done" {
		t.Fatalf("fim: %+v", res)
	}
	b, err := os.ReadFile(file)
	if err != nil || !strings.HasPrefix(string(b), "#") {
		t.Fatalf("simulation file: %q %v", b, err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("simulation file not cleaned up")
	}

	// FIM 未监控该目录时不适用，而不是假装执行。
	a.cfg.FIMPaths = []string{"/somewhere/else"}
	if res := a.runCommand(model.AgentCommand{ID: "sim-0000abce", Type: "simulate", Scenario: "fim"}); res.Status != "not_applicable" {
		t.Errorf("unmonitored fim: %+v", res)
	}

	if runtime.GOOS != "linux" {
		if res := a.runCommand(model.AgentCommand{ID: "sim-0000abcf", Type: "simulate", Scenario: "process"}); res.Status != "not_applicable" {
			t.Errorf("process on %s: %+v", runtime.GOOS, res)
		}
	}

	// 测试进程：用当前测试程序代替 Agent，确认参数校验。
	if code := childExitCode(t, "abc"); code != 2 {
		t.Errorf("invalid seconds: exit %d", code)
	}

	// 蜜罐：发送自检标记并收到确认。
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- line
		c.Write([]byte("OK\n"))
		c.Close()
	}()
	res = a.runCommand(model.AgentCommand{ID: "sim-0000abd0", Type: "simulate", Scenario: "honeypot",
		Params: map[string]string{"target": ln.Addr().String()}})
	if res.Status != "done" || <-got != "SAFE-SIMULATION sim-0000abd0\n" {
		t.Errorf("honeypot: %+v", res)
	}

	// 不在白名单内的指令一律拒绝。
	for _, bad := range []model.AgentCommand{
		{ID: "sim-0000abd1", Type: "exec", Scenario: "fim"},
		{ID: "sim-0000abd2", Type: "simulate", Scenario: "rm -rf /"},
		{ID: "../../etc/passwd", Type: "simulate", Scenario: "fim"},
	} {
		if res := a.runCommand(bad); res.Status != "error" {
			t.Errorf("command %+v accepted: %+v", bad, res)
		}
	}
}

// childExitCode 以自检测试进程的方式运行当前测试二进制，返回退出码。
func childExitCode(t *testing.T, secs string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestSimulationChildHelper")
	cmd.Env = append(os.Environ(), "SAFE_SIM_CHILD="+secs)
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 0
}

func TestSimulationChildHelper(t *testing.T) {
	secs := os.Getenv("SAFE_SIM_CHILD")
	if secs == "" {
		t.Skip("helper process")
	}
	os.Args = []string{os.Args[0], SimulationChildArg, secs}
	RunSimulationChildIfRequested()
}

func TestSimLogin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not applicable on Windows")
	}
	cases := []struct {
		scenario       string
		failed, logins int
		user           string
	}{
		{"brute_force", 10, 0, ""},
		{"brute_force_login", 10, 1, "safe-sim"},
		{"root_login", 0, 1, "root"},
	}
	for _, c := range cases {
		a := &Agent{}
		res := a.runCommand(model.AgentCommand{ID: "sim-0000abcd", Type: "simulate", Scenario: c.scenario})
		if res.Status != "done" {
			t.Fatalf("%s: %+v", c.scenario, res)
		}
		failed, logins := 0, 0
		for _, ev := range a.takeExecEvents() {
			if ev.SimulationID != "sim-0000abcd" || !strings.HasPrefix(ev.SrcIP, "192.0.2.") {
				t.Errorf("%s: %+v", c.scenario, ev)
			}
			switch ev.Type {
			case model.EventLoginFailed:
				failed++
			case model.EventLoginSuccess:
				logins++
				if ev.User != c.user {
					t.Errorf("%s: user %q", c.scenario, ev.User)
				}
			}
		}
		if failed != c.failed || logins != c.logins {
			t.Errorf("%s: failed %d logins %d", c.scenario, failed, logins)
		}
	}
}
