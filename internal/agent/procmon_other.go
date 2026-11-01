//go:build !linux

package agent

import (
	"context"
	"errors"
)

func startProcMonitor(context.Context, func(ExecInfo)) error {
	return errors.New("process monitoring is only supported on Linux")
}
