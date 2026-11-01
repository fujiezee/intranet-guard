package agent

import (
	"log/slog"

	"safe/internal/model"
)

// winlogQuery / winlogLatest 由 Windows 平台实现（winlog_windows.go），其他平台为 nil。
var (
	winlogQuery  func(channel string, after uint64, max int) ([]WinEvent, error)
	winlogLatest func(channel string) (uint64, error)
)

var winChannels = []string{"Security", "System"}

const (
	winBatch        = 1000
	winMaxPerCycle  = 20000 // 单个周期每个日志最多处理的事件数，繁忙的域控上积压会在后续周期追上
	winBacklogAlarm = 50000
)

// collectWinlog 读取上次位置之后的事件日志并转换为主机事件。首次运行只记录当前位置（建立基线）。
// 读取位置立即推进：生成的事件由调用方放入缓冲区，上报失败时保留重试，而不是重新读取。
func (a *Agent) collectWinlog() []model.HostEvent {
	if winlogQuery == nil {
		return nil
	}
	if a.winBookmarks == nil {
		a.winBookmarks = map[string]uint64{}
	}
	var out []model.HostEvent
	for _, ch := range winChannels {
		latest, err := winlogLatest(ch)
		if err != nil {
			slog.Warn("read event log", "channel", ch, "err", err)
			continue
		}
		pos, ok := a.winBookmarks[ch]
		if !ok || latest < pos { // 首次运行，或日志被清除后编号重新开始
			a.winBookmarks[ch] = latest
			continue
		}
		for n := 0; n < winMaxPerCycle && pos < latest; {
			evs, err := winlogQuery(ch, pos, winBatch)
			if err != nil {
				slog.Warn("query event log", "channel", ch, "err", err)
				break
			}
			if len(evs) == 0 {
				break
			}
			for _, ev := range evs {
				if ev.RecordID <= pos {
					continue
				}
				pos = ev.RecordID
				ev.Channel = ch
				out = append(out, a.win.Evaluate(ev)...)
			}
			n += len(evs)
		}
		if latest-pos > winBacklogAlarm {
			slog.Warn("event log backlog", "channel", ch, "pending", latest-pos)
		}
		a.winBookmarks[ch] = pos
	}
	if a.win.execSeen && !a.hasCapability("exec_monitor") {
		a.info.Capabilities = append(a.info.Capabilities, "exec_monitor")
		slog.Info("command auditing active (Security event 4688)")
	}
	return out
}
