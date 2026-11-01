package agent

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
)

var (
	// 传统 syslog：Nov  1 09:04:19 host sshd[123]: msg
	reSyslog = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) \S+ ([\w.-]+)(?:\[\d+\])?: (.*)$`)
	// rsyslog 高精度格式 / journalctl -o short-iso：2026-11-01T09:04:19.123+08:00 host sshd[123]: msg
	reISO = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) \S+ ([\w.-]+)(?:\[\d+\])?: (.*)$`)

	reRepeated = regexp.MustCompile(`^message repeated (\d+) times: \[ ?(.*?) ?\]$`)
	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	reFailed   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S*) from (\S+) port \d+`)
	reSudo     = regexp.MustCompile(`^\s*(\S+) : .*?(?:USER=(\S+) ; )?COMMAND=(.*)$`)
)

// ParseAuthLine 解析一行 auth 日志，返回其中的 SSH 登录与 sudo 事件。
// now 用于补全传统 syslog 时间戳中缺失的年份。
func ParseAuthLine(line string, now time.Time) []model.HostEvent {
	ts, prog, msg, ok := splitSyslog(line, now)
	if !ok {
		return nil
	}

	count := 1
	if m := reRepeated.FindStringSubmatch(msg); m != nil {
		count, _ = strconv.Atoi(m[1])
		msg = m[2]
	}

	var ev model.HostEvent
	switch {
	case prog == "sshd" || prog == "sshd-session": // OpenSSH 9.8+ 拆出了 sshd-session
		if m := reAccepted.FindStringSubmatch(msg); m != nil {
			ev = model.HostEvent{Type: model.EventLoginSuccess, User: m[2], SrcIP: m[3], Detail: "ssh " + m[1]}
		} else if m := reFailed.FindStringSubmatch(msg); m != nil {
			ev = model.HostEvent{Type: model.EventLoginFailed, User: m[2], SrcIP: m[3], Detail: "ssh " + m[1]}
		} else {
			return nil
		}
	case prog == "sudo":
		m := reSudo.FindStringSubmatch(msg)
		if m == nil {
			return nil
		}
		target := m[2]
		if target == "" {
			target = "root"
		}
		ev = model.HostEvent{Type: model.EventSudo, User: m[1], Detail: "as " + target + ": " + strings.TrimSpace(m[3])}
	default:
		return nil
	}

	ev.Time = ts
	events := make([]model.HostEvent, count)
	for i := range events {
		events[i] = ev
	}
	return events
}

func splitSyslog(line string, now time.Time) (ts time.Time, prog, msg string, ok bool) {
	if m := reISO.FindStringSubmatch(line); m != nil {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
			if t, err := time.Parse(layout, m[1]); err == nil {
				return t, m[2], m[3], true
			}
		}
		return ts, "", "", false
	}
	if m := reSyslog.FindStringSubmatch(line); m != nil {
		t, err := time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(now.Year())+" "+m[1], now.Location())
		if err != nil {
			return ts, "", "", false
		}
		// 跨年：12 月的日志在 1 月读取时，补上的年份会落在未来。
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, m[2], m[3], true
	}
	return ts, "", "", false
}
