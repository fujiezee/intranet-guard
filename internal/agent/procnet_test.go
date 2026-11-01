//go:build linux

package agent

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseProcNetAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"0A00A8C0:115C":                         "192.168.0.10:4444",
		"00000000000000000000000001000000:0016": "[::1]:22",
	} {
		if got := parseProcNetAddr(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

// 不需要 root：启动一个标准输入输出连到 TCP 的 shell，从 /proc 读取后应判定为反弹 shell；
// 普通 shell 不应命中。命令行读取与规则匹配是真实执行的，只有内核事件推送需要 root（由端到端测试覆盖）。
func TestReadExecInfoReverseShell(t *testing.T) {
	simDuration = 3 * time.Second
	t.Cleanup(func() { simDuration = 120 * time.Second })

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			time.Sleep(4 * time.Second)
		}
	}()
	client, _ := net.Dial("tcp", ln.Addr().String())
	defer client.Close()
	f, _ := client.(*net.TCPConn).File()
	pid, err := startShell("sleep 3; : safe-sim sim-0000aaaa", f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := readExecInfo(pid, &userCache{m: map[string]string{}})
	if !ok || !e.StdioNetwork || !strings.HasPrefix(e.StdioRemote, "127.0.0.1:") || !strings.Contains(e.Cmdline, "sim-0000aaaa") {
		t.Fatalf("exec info: %+v", e)
	}
	found := false
	for _, fd := range EvaluateExec(e) {
		if fd.Rule == "reverse_shell" {
			found = true
		}
	}
	if !found {
		t.Errorf("reverse shell not detected: %+v", e)
	}

	pid, err = startShell("sleep 3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := readExecInfo(pid, &userCache{m: map[string]string{}}); e.StdioNetwork || len(EvaluateExec(e)) != 0 {
		t.Errorf("plain shell flagged: %+v", e)
	}
}
