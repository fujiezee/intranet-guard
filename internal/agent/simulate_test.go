package agent

import (
	"bufio"
	"net"
	"os"
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
