//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// 以下测试在真实 Windows 上运行（CI 的 Windows 任务），调用真实的系统接口。

func TestWinlogAPI(t *testing.T) {
	latest, err := latestWinlogRecord("System")
	if err != nil || latest == 0 {
		t.Fatalf("latest System record: %d %v", latest, err)
	}
	from := uint64(0)
	if latest > 20 {
		from = latest - 20
	}
	evs, err := queryWinlog("System", from, 100)
	if err != nil || len(evs) == 0 {
		t.Fatalf("query: %d events, %v", len(evs), err)
	}
	for _, e := range evs {
		if e.RecordID <= from || e.ID == 0 || e.Time.IsZero() {
			t.Errorf("bad event: %+v", e)
		}
	}
	// 书签定位失败（记录号超出范围）时退回按记录号过滤，结果为空而不是报错
	if evs, err := queryWinlog("System", latest+1000000, 10); err != nil || len(evs) != 0 {
		t.Errorf("query beyond latest: %d %v", len(evs), err)
	}
	if _, err := latestWinlogRecord("Security"); err != nil {
		t.Errorf("Security log not readable (needs administrator): %v", err)
	}
}

func TestWinKillProcess(t *testing.T) {
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\PING.EXE`), "-n", "60", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exe, err := processExe(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := killProcess(strconv.Itoa(cmd.Process.Pid), `C:\Windows\System32\notepad.exe`); err == nil {
		t.Error("killed a process whose executable does not match")
	}
	// 路径大小写不同也视为同一程序
	if _, err := killProcess(strconv.Itoa(cmd.Process.Pid), filepath.Join(filepath.Dir(exe), "ping.exe")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("process still running")
	}
}

func TestWinProtectedPaths(t *testing.T) {
	root := os.Getenv("SystemRoot")
	for path, want := range map[string]bool{
		filepath.Join(root, `System32\kernel32.dll`):            true,
		`c:\windows\system32\drivers\etc\hosts`:                 true,
		filepath.Join(os.Getenv("ProgramFiles"), `App\app.exe`): true,
		`C:\inetpub\wwwroot\shell.aspx`:                         false,
		`C:\Users\Public\evil.exe`:                              false,
	} {
		if got := isProtectedPath(path); got != want {
			t.Errorf("isProtectedPath(%q) = %v, want %v", path, got, want)
		}
	}
}
