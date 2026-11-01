package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
)

// 从这些目录运行的程序在服务器上很少是正常业务，常见于挖矿、木马落地。
var suspiciousDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// ScanProcesses 找出从临时目录运行、或磁盘文件已被删除仍在运行的进程。
// 返回的 key 为 "pid:exe"，调用方用它去重，同一进程只上报一次。
func ScanProcesses(now time.Time) map[string]model.HostEvent {
	out := map[string]model.HostEvent{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue // 内核线程或无权限
		}
		reason := ""
		switch {
		case strings.HasSuffix(exe, " (deleted)"):
			reason = "executable deleted from disk"
		default:
			for _, d := range suspiciousDirs {
				if strings.HasPrefix(exe, d) {
					reason = "running from " + strings.TrimSuffix(d, "/")
				}
			}
		}
		if reason == "" {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		cmd := strings.TrimSpace(strings.ReplaceAll(string(cmdline), "\x00", " "))
		if len(cmd) > 512 {
			cmd = cmd[:512]
		}
		out[strconv.Itoa(pid)+":"+exe] = model.HostEvent{
			Type: model.EventSuspiciousProcess, Time: now, Path: exe,
			Detail: "pid " + strconv.Itoa(pid) + ", " + reason + ", cmdline: " + cmd,
		}
	}
	return out
}
