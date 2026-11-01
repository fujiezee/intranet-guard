//go:build !windows

package agent

import (
	"os"
	"strconv"
	"syscall"
)

func processExe(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
}

func forceKill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
