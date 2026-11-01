//go:build !linux

package agent

import (
	"time"

	"safe/internal/model"
)

// ScanProcesses 目前只支持 Linux。
func ScanProcesses(time.Time) map[string]model.HostEvent { return map[string]model.HostEvent{} }
