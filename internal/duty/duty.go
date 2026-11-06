// Package duty 生成交接班消息和日报 / 周报，并按时推送到告警推送渠道。
package duty

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/notify"
	"safe/internal/store"
)

// 报表在每天 / 每周一的这个时刻（管理中心所在时区）生成并推送
const reportHour = 9

// 管理中心停机错过推送时刻太久时，补生成的报表只保存、不推送，避免在不合适的时间往群里发旧报表
const pushGrace = 6 * time.Hour

// Period 返回 now 时刻最近一份应生成的报表：计划生成时间和统计周期 [from, to)。
func Period(kind string, now time.Time, loc *time.Location) (sched, from, to time.Time) {
	now = now.In(loc)
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	if kind == store.ReportWeekly {
		day = day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7)) // 本周一
		if now.Before(day.Add(reportHour * time.Hour)) {
			day = day.AddDate(0, 0, -7)
		}
		return day.Add(reportHour * time.Hour), day.AddDate(0, 0, -7), day
	}
	if now.Before(day.Add(reportHour * time.Hour)) {
		day = day.AddDate(0, 0, -1)
	}
	return day.Add(reportHour * time.Hour), day.AddDate(0, 0, -1), day
}

// Run 每分钟检查一次是否该生成报表。active 为 false 时跳过（多实例部署时只由主实例生成）。
func Run(ctx context.Context, st *store.Store, active func() bool) {
	hc := &http.Client{Timeout: 10 * time.Second}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if active() {
			if err := RunOnce(ctx, st, hc, time.Now(), time.Local); err != nil {
				slog.Warn("duty report", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce 生成尚未生成的最近一份日报和周报，并推送到接收该报表的渠道。
func RunOnce(ctx context.Context, st *store.Store, hc *http.Client, now time.Time, loc *time.Location) error {
	for _, kind := range []string{store.ReportDaily, store.ReportWeekly} {
		sched, from, to := Period(kind, now, loc)
		if ok, err := st.HasReport(ctx, kind, from); err != nil || ok {
			if err != nil {
				return err
			}
			continue
		}
		data, err := st.BuildReport(ctx, from, to, now)
		if err != nil {
			return err
		}
		r, created, err := st.InsertReport(ctx, kind, from, to, data)
		if err != nil || !created {
			return err
		}
		slog.Info("report generated", "kind", kind, "from", from.Format(time.DateOnly))
		if now.Sub(sched) > pushGrace {
			continue
		}
		title, text := FormatReport(r, loc)
		push(ctx, st, hc, func(ch model.NotifyChannel) bool {
			return (kind == store.ReportDaily && ch.DailyReport) || (kind == store.ReportWeekly && ch.WeeklyReport)
		}, title, text, map[string]any{"title": title, "text": text, "report": r})
	}
	return nil
}

// PushHandover 把交接班记录推送到所有启用的渠道。
func PushHandover(ctx context.Context, st *store.Store, h store.Handover, loc *time.Location) {
	title, text := FormatHandover(h, loc)
	push(ctx, st, &http.Client{Timeout: 10 * time.Second}, func(model.NotifyChannel) bool { return true },
		title, text, map[string]any{"title": title, "text": text, "handover": h})
}

func push(ctx context.Context, st *store.Store, hc *http.Client, want func(model.NotifyChannel) bool, title, text string, webhook any) {
	channels, err := st.ListChannels(ctx)
	if err != nil {
		slog.Warn("list notify channels", "err", err)
		return
	}
	for _, ch := range channels {
		if !ch.Enabled || !want(ch) {
			continue
		}
		err := notify.SendMessage(ctx, hc, ch, title, text, webhook)
		if err != nil {
			slog.Warn("duty notification failed", "channel", ch.Name, "title", title, "err", err)
		}
		_ = st.RecordChannelResult(ctx, ch.ID, err)
	}
}

var sevLabel = map[model.Severity]string{model.SeverityHigh: "高", model.SeverityMedium: "中", model.SeverityLow: "低"}

// FormatDuration 把秒数写成"8 分钟""1.5 小时""2.3 天"。
func FormatDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", sec)
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 48*time.Hour:
		return trimZero(fmt.Sprintf("%.1f", d.Hours())) + " 小时"
	}
	return trimZero(fmt.Sprintf("%.1f", d.Hours()/24)) + " 天"
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

func bySeverity(m map[model.Severity]int) string {
	return fmt.Sprintf("高 %d / 中 %d / 低 %d", m[model.SeverityHigh], m[model.SeverityMedium], m[model.SeverityLow])
}

func avg(sec int64, n int) string {
	if n == 0 {
		return "—"
	}
	return FormatDuration(sec)
}

func percent(part, total int) string {
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%%（%d/%d）", float64(part)*100/float64(total), part, total)
}

func metricLines(b *strings.Builder, m store.DutyMetrics) {
	total := 0
	for _, n := range m.Alerts {
		total += n
	}
	fmt.Fprintf(b, "- 新告警 %d（%s），误报率 %s\n", total, bySeverity(m.Alerts), percent(m.FalsePositives, m.Handled))
	fmt.Fprintf(b, "- 新事件 %d，结案 %d\n", m.Incidents, m.Resolved)
	fmt.Fprintf(b, "- 平均响应 %s，平均处置 %s，SLA 达标率 %s\n", avg(m.MTTA, m.MTTASamples), avg(m.MTTR, m.MTTRSamples), percent(m.SLAMet, m.SLATotal))
}

func itemLine(it store.DutyItem) string {
	title := it.Title
	if it.Kind == "incident" {
		title = fmt.Sprintf("事件 #%d：%s", it.ID, it.Title)
	}
	line := fmt.Sprintf("- [%s] %s", sevLabel[it.Severity], title)
	if it.Assignee != "" {
		line += "（" + it.Assignee + "）"
	}
	return line
}

func FormatHandover(h store.Handover, loc *time.Location) (title, text string) {
	title = "【内网防护】交接班：" + h.Author
	var b strings.Builder
	b.WriteString(title + "\n")
	fmt.Fprintf(&b, "%s – %s\n", h.From.In(loc).Format("01-02 15:04"), h.To.In(loc).Format("01-02 15:04"))
	metricLines(&b, h.Summary.Metrics)
	fmt.Fprintf(&b, "- 遗留待办 %d 项，已超时 %d 项\n", h.Summary.OpenTotal, h.Summary.OpenOverdue)
	for _, it := range h.Summary.Open {
		b.WriteString("  " + itemLine(it) + "\n")
	}
	if h.Summary.OpenTotal > len(h.Summary.Open) {
		fmt.Fprintf(&b, "  …另有 %d 项\n", h.Summary.OpenTotal-len(h.Summary.Open))
	}
	if note := strings.TrimSpace(h.Note); note != "" {
		b.WriteString("\n备注：\n" + note + "\n")
	}
	return title, strings.TrimRight(b.String(), "\n")
}

// ReportTitle 返回报表标题，如"日报 11-05""周报 10-26 – 11-01"。
func ReportTitle(r store.Report, loc *time.Location) string {
	from := r.PeriodStart.In(loc)
	if r.Kind == store.ReportWeekly {
		return fmt.Sprintf("周报 %s – %s", from.Format("01-02"), r.PeriodEnd.In(loc).AddDate(0, 0, -1).Format("01-02"))
	}
	return "日报 " + from.Format("01-02")
}

func FormatReport(r store.Report, loc *time.Location) (title, text string) {
	title = "【内网防护】" + ReportTitle(r, loc)
	d := r.Data
	var b strings.Builder
	b.WriteString(title + "\n\n**值守**\n")
	metricLines(&b, d.Metrics)
	if d.Metrics.MTTDSamples > 0 {
		fmt.Fprintf(&b, "- 攻击模拟自检 %d 次，平均发现 %s\n", d.Metrics.MTTDSamples, FormatDuration(d.Metrics.MTTD))
	}
	b.WriteString("\n**漏洞**\n")
	fmt.Fprintf(&b, "- 新发现 %s，已修复 %s\n", bySeverity(d.NewVulns), bySeverity(d.FixedVulns))
	b.WriteString("\n**生成时未处理**\n")
	sum := func(m map[string]int) int {
		n := 0
		for _, v := range m {
			n += v
		}
		return n
	}
	fmt.Fprintf(&b, "- 事件 %d，告警 %d，漏洞 %d\n", sum(d.OpenIncidents), sum(d.OpenAlerts), sum(d.OpenVulns))
	if len(d.TopAssets) > 0 {
		b.WriteString("\n**风险最高的资产**\n")
		for _, a := range d.TopAssets {
			line := fmt.Sprintf("- %s", a.IP)
			if a.Name != "" {
				line += " " + a.Name
			}
			line += fmt.Sprintf("：%d 分", a.Risk)
			if a.Owner != "" {
				line += "（" + a.Owner + "）"
			}
			b.WriteString(line + "\n")
		}
	}
	if len(d.OfflineAgents) > 0 || len(d.OfflineProbes) > 0 {
		b.WriteString("\n**离线节点**\n")
		if n := len(d.OfflineAgents); n > 0 {
			names := []string{}
			for _, a := range d.OfflineAgents[:min(n, 10)] {
				name := a.Hostname
				if name == "" {
					name = a.ID
				}
				names = append(names, name)
			}
			fmt.Fprintf(&b, "- Agent %d 台：%s", n, strings.Join(names, "、"))
			if n > 10 {
				b.WriteString(" 等")
			}
			b.WriteString("\n")
		}
		if n := len(d.OfflineProbes); n > 0 {
			fmt.Fprintf(&b, "- 探针 %d 个：%s\n", n, strings.Join(d.OfflineProbes, "、"))
		}
	}
	return title, strings.TrimRight(b.String(), "\n")
}
