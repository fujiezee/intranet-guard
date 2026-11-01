package agent

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/tail"
)

// ReadAuthFile 从上次位置继续读取认证日志并解析事件，返回新的读取位置。
// 首次运行（state 为空）直接跳到文件末尾，不上报历史日志。
func ReadAuthFile(path string, state *tail.State, now time.Time) ([]model.HostEvent, *tail.State, error) {
	lines, next, err := tail.ReadLines(path, state)
	var events []model.HostEvent
	for _, line := range lines {
		events = append(events, ParseAuthLine(string(line), now)...)
	}
	return events, next, err
}

// ReadJournal 读取 journald 中 sshd / sudo 的新日志，用于没有 auth.log 的发行版。
// cursor 为空时只获取当前位置，不上报历史日志。
func ReadJournal(ctx context.Context, cursor string, now time.Time) ([]model.HostEvent, string, error) {
	if cursor == "" {
		// 取整个 journal 的最新位置（不带过滤条件，保证一定有输出）。
		out, err := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "cat", "-n", "1", "--show-cursor").Output()
		if err != nil {
			return nil, "", err
		}
		_, c := parseJournal(out, now)
		return nil, c, nil
	}

	out, err := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "short-iso", "--show-cursor",
		"--after-cursor", cursor, "-n", "20000",
		"_COMM=sshd", "+", "_COMM=sshd-session", "+", "_COMM=sudo").Output()
	if err != nil {
		return nil, cursor, err
	}
	events, c := parseJournal(out, now)
	if c == "" {
		c = cursor // 没有新日志
	}
	return events, c, nil
}

func parseJournal(out []byte, now time.Time) ([]model.HostEvent, string) {
	var events []model.HostEvent
	var cursor string
	for _, line := range strings.Split(string(out), "\n") {
		if c, ok := strings.CutPrefix(line, "-- cursor: "); ok {
			cursor = strings.TrimSpace(c)
			continue
		}
		events = append(events, ParseAuthLine(line, now)...)
	}
	return events, cursor
}
