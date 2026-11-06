package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"safe/internal/model"
)

// --- 值守工作台：SLA、待办队列、指标、交接班、日报 / 周报 ---

// SLA 时限（分钟），按级别；0 表示不计时。
// Response：告警或事件产生到被确认 / 认领；Resolve：事件产生到结案（告警确认即处理完毕，只计响应）。
type SLA struct {
	Response map[model.Severity]int `json:"response"`
	Resolve  map[model.Severity]int `json:"resolve"`
}

var DefaultSLA = SLA{
	Response: map[model.Severity]int{model.SeverityHigh: 15, model.SeverityMedium: 120, model.SeverityLow: 1440},
	Resolve:  map[model.Severity]int{model.SeverityHigh: 240, model.SeverityMedium: 4320, model.SeverityLow: 0},
}

const slaKey = "duty.sla"

func (s *Store) GetSLA(ctx context.Context) (SLA, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, slaKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSLA, nil
	} else if err != nil {
		return SLA{}, err
	}
	var c SLA
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return DefaultSLA, nil
	}
	return c, nil
}

func (s *Store) SetSLA(ctx context.Context, c SLA) error {
	raw, _ := json.Marshal(c)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		slaKey, string(raw))
	return err
}

func (c SLA) due(limits map[model.Severity]int, sev model.Severity, from time.Time) *time.Time {
	m := limits[sev]
	if m <= 0 {
		return nil
	}
	t := from.Add(time.Duration(m) * time.Minute).UTC()
	return &t
}

// slaOutcome：已响应的按响应时间判断；未响应且已超时的计为未达标；未响应也未到期的不计入。
func slaOutcome(due, done *time.Time, now time.Time) (counted, met bool) {
	switch {
	case due == nil:
		return false, false
	case done != nil:
		return true, !done.After(*due)
	case now.After(*due):
		return true, false
	}
	return false, false
}

// DutyItem 是待办队列中的一项：未结事件，或不属于任何事件的未处理告警（属于事件的告警随事件处理）。
type DutyItem struct {
	Kind        string         `json:"kind"` // incident / alert
	ID          int64          `json:"id"`
	Title       string         `json:"title"`
	Severity    model.Severity `json:"severity"`
	IP          string         `json:"ip"`
	Status      string         `json:"status"`
	Assignee    string         `json:"assignee,omitempty"`
	AlertCount  int            `json:"alert_count,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	AckedAt     *time.Time     `json:"acked_at,omitempty"`
	ResponseDue *time.Time     `json:"response_due,omitempty"`
	ResolveDue  *time.Time     `json:"resolve_due,omitempty"`
}

// Overdue 表示当前已超出时限：未认领超过响应时限，或事件未结案超过处置时限。
func (it DutyItem) Overdue(now time.Time) bool {
	if it.AckedAt == nil && it.ResponseDue != nil && now.After(*it.ResponseDue) {
		return true
	}
	return it.ResolveDue != nil && now.After(*it.ResolveDue)
}

const queueAlertLimit = 1000

// DutyQueue 返回待办队列，按级别从高到低、同级按产生时间从早到晚排列。
func (s *Store) DutyQueue(ctx context.Context) ([]DutyItem, error) {
	sla, err := s.GetSLA(ctx)
	if err != nil {
		return nil, err
	}
	var incidents []model.Incident
	for _, status := range []model.IncidentStatus{model.IncidentOpen, model.IncidentInvestigating} {
		list, err := s.ListIncidents(ctx, status)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, list...)
	}
	items := []DutyItem{}
	for _, in := range incidents {
		items = append(items, DutyItem{
			Kind: "incident", ID: in.ID, Title: in.Title, Severity: in.Severity, IP: in.IP, Status: string(in.Status),
			Assignee: in.Assignee, AlertCount: in.AlertCount, CreatedAt: in.CreatedAt, AckedAt: in.AckedAt,
			ResponseDue: sla.due(sla.Response, in.Severity, in.CreatedAt),
			ResolveDue:  sla.due(sla.Resolve, in.Severity, in.CreatedAt),
		})
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, severity, ip, message, created_at FROM alerts
		WHERE status = ? AND incident_id = 0 AND resolution <> ?
		ORDER BY id DESC LIMIT ?`, model.AlertOpen, model.ResolutionSimulation, queueAlertLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		it := DutyItem{Kind: "alert", Status: string(model.AlertOpen)}
		var typ string
		if err := rows.Scan(&it.ID, &typ, &it.Severity, &it.IP, &it.Title, &it.CreatedAt); err != nil {
			return nil, err
		}
		it.ResponseDue = sla.due(sla.Response, it.Severity, it.CreatedAt)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		return a.CreatedAt.Before(b.CreatedAt)
	})
	return items, nil
}

// DutyMetrics 统计 [From, To) 期间产生的告警和事件。时长单位为秒，样本数为 0 时时长无意义。
type DutyMetrics struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// 新告警（不含攻击模拟自检），按级别
	Alerts map[model.Severity]int `json:"alerts"`
	// 已由值守人员确认的告警数和其中的误报数
	Handled        int `json:"handled"`
	FalsePositives int `json:"false_positives"`
	Incidents      int `json:"incidents"`
	// 期间结案的事件（不论何时产生）
	Resolved int `json:"resolved"`
	// 平均响应时长：产生到确认 / 认领（不属于事件的告警和事件）
	MTTA        int64 `json:"mtta_seconds"`
	MTTASamples int   `json:"mtta_samples"`
	// 平均处置时长：事件产生到结案
	MTTR        int64 `json:"mttr_seconds"`
	MTTRSamples int   `json:"mttr_samples"`
	// 平均发现时长：攻击模拟自检从执行到产生告警
	MTTD        int64 `json:"mttd_seconds"`
	MTTDSamples int   `json:"mttd_samples"`
	// SLA：计入的项数（已响应或已超时）和其中达标的项数，响应与处置时限分别计
	SLATotal int `json:"sla_total"`
	SLAMet   int `json:"sla_met"`
}

func (s *Store) DutyMetrics(ctx context.Context, from, to, now time.Time) (DutyMetrics, error) {
	from, to = from.UTC(), to.UTC()
	m := DutyMetrics{From: from, To: to, Alerts: map[model.Severity]int{}}
	sla, err := s.GetSLA(ctx)
	if err != nil {
		return m, err
	}
	var mtta, mttr, mttd time.Duration
	count := func(due, done *time.Time) {
		if counted, met := slaOutcome(due, done, now); counted {
			m.SLATotal++
			if met {
				m.SLAMet++
			}
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT severity, incident_id, resolution, created_at, acked_at FROM alerts
		WHERE created_at >= ? AND created_at < ? AND resolution <> ?`, from, to, model.ResolutionSimulation)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var sev model.Severity
		var incidentID int64
		var resolution string
		var created time.Time
		var acked sql.NullTime
		if err := rows.Scan(&sev, &incidentID, &resolution, &created, &acked); err != nil {
			rows.Close()
			return m, err
		}
		m.Alerts[sev]++
		if acked.Valid {
			m.Handled++
			if resolution == model.ResolutionFalsePositive {
				m.FalsePositives++
			}
		}
		if incidentID != 0 {
			continue // 随事件计入响应和 SLA
		}
		if acked.Valid {
			mtta += acked.Time.Sub(created)
			m.MTTASamples++
		}
		count(sla.due(sla.Response, sev, created), timePtr(acked))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}

	rows, err = s.db.QueryContext(ctx, `
		SELECT severity, created_at, acked_at, resolved_at FROM incidents WHERE created_at >= ? AND created_at < ?`, from, to)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var sev model.Severity
		var created time.Time
		var acked, resolved sql.NullTime
		if err := rows.Scan(&sev, &created, &acked, &resolved); err != nil {
			rows.Close()
			return m, err
		}
		m.Incidents++
		if acked.Valid {
			mtta += acked.Time.Sub(created)
			m.MTTASamples++
		}
		if resolved.Valid {
			mttr += resolved.Time.Sub(created)
			m.MTTRSamples++
		}
		count(sla.due(sla.Response, sev, created), timePtr(acked))
		count(sla.due(sla.Resolve, sev, created), timePtr(resolved))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE resolved_at >= ? AND resolved_at < ?`, from, to).
		Scan(&m.Resolved); err != nil {
		return m, err
	}

	rows, err = s.db.QueryContext(ctx, `
		SELECT latency_ms FROM simulations WHERE status = ? AND finished_at >= ? AND finished_at < ?`, model.SimPassed, from, to)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var ms int64
		if err := rows.Scan(&ms); err != nil {
			rows.Close()
			return m, err
		}
		mttd += time.Duration(ms) * time.Millisecond
		m.MTTDSamples++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}

	avg := func(total time.Duration, n int) int64 {
		if n == 0 {
			return 0
		}
		return int64((total / time.Duration(n)).Seconds())
	}
	m.MTTA, m.MTTR, m.MTTD = avg(mtta, m.MTTASamples), avg(mttr, m.MTTRSamples), avg(mttd, m.MTTDSamples)
	return m, nil
}

// --- 交接班 ---

// HandoverSummary 是交接时自动生成的汇总：本班的指标和交接时仍未处理的事项。
type HandoverSummary struct {
	Metrics DutyMetrics `json:"metrics"`
	// 交接时未处理的事项数、其中已超时的数量，以及级别最高的若干项
	OpenTotal   int        `json:"open_total"`
	OpenOverdue int        `json:"open_overdue"`
	Open        []DutyItem `json:"open"`
}

type Handover struct {
	ID        int64           `json:"id"`
	Author    string          `json:"author"`
	From      time.Time       `json:"from"`
	To        time.Time       `json:"to"`
	Note      string          `json:"note"`
	Summary   HandoverSummary `json:"summary"`
	CreatedAt time.Time       `json:"created_at"`
}

// 第一次交接没有上一班时，从 12 小时前算起
const firstShift = 12 * time.Hour

const handoverOpenItems = 15

// PreviewHandover 生成从上次交接到 now 的汇总，不保存。
// 时间截到微秒（PostgreSQL 的精度），保存后读回的交接时间与返回值一致。
func (s *Store) PreviewHandover(ctx context.Context, now time.Time) (Handover, error) {
	now = now.UTC().Truncate(time.Microsecond)
	h := Handover{From: now.Add(-firstShift), To: now}
	if last, err := s.ListHandovers(ctx, 1); err != nil {
		return h, err
	} else if len(last) > 0 && last[0].To.Before(now) {
		h.From = last[0].To
	}
	m, err := s.DutyMetrics(ctx, h.From, h.To, now)
	if err != nil {
		return h, err
	}
	queue, err := s.DutyQueue(ctx)
	if err != nil {
		return h, err
	}
	h.Summary = HandoverSummary{Metrics: m, OpenTotal: len(queue), Open: queue[:min(len(queue), handoverOpenItems)]}
	for _, it := range queue {
		if it.Overdue(now) {
			h.Summary.OpenOverdue++
		}
	}
	return h, nil
}

// CreateHandover 保存一次交接。
func (s *Store) CreateHandover(ctx context.Context, author, note string, now time.Time) (Handover, error) {
	h, err := s.PreviewHandover(ctx, now)
	if err != nil {
		return h, err
	}
	h.Author, h.Note, h.CreatedAt = author, note, h.To
	raw, _ := json.Marshal(h.Summary)
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO handovers (author, from_at, to_at, summary, note, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		h.Author, h.From, h.To, string(raw), h.Note, h.CreatedAt).Scan(&h.ID)
	return h, err
}

func (s *Store) ListHandovers(ctx context.Context, limit int) ([]Handover, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, author, from_at, to_at, summary, note, created_at FROM handovers ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Handover{}
	for rows.Next() {
		var h Handover
		var raw string
		if err := rows.Scan(&h.ID, &h.Author, &h.From, &h.To, &raw, &h.Note, &h.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &h.Summary)
		h.From, h.To, h.CreatedAt = h.From.UTC(), h.To.UTC(), h.CreatedAt.UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// --- 日报 / 周报 ---

const (
	ReportDaily  = "daily"
	ReportWeekly = "weekly"
)

type ReportAsset struct {
	IP      string   `json:"ip"`
	Name    string   `json:"name,omitempty"`
	Owner   string   `json:"owner,omitempty"`
	Risk    int      `json:"risk"`
	Reasons []string `json:"reasons,omitempty"`
}

type ReportAgent struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"last_seen"`
}

// ReportData 是一份报表的内容：期间的值守指标和漏洞变化，以及生成时的未处理数和节点状态。
type ReportData struct {
	Metrics       DutyMetrics            `json:"metrics"`
	NewVulns      map[model.Severity]int `json:"new_vulns"`
	FixedVulns    map[model.Severity]int `json:"fixed_vulns"`
	OpenIncidents map[string]int         `json:"open_incidents"`
	OpenAlerts    map[string]int         `json:"open_alerts"`
	OpenVulns     map[string]int         `json:"open_vulns"`
	TopAssets     []ReportAsset          `json:"top_assets"`
	OfflineAgents []ReportAgent          `json:"offline_agents"`
	OfflineProbes []string               `json:"offline_probes"`
}

type Report struct {
	ID          int64       `json:"id"`
	Kind        string      `json:"kind"`
	PeriodStart time.Time   `json:"period_start"`
	PeriodEnd   time.Time   `json:"period_end"`
	CreatedAt   time.Time   `json:"created_at"`
	Data        *ReportData `json:"data,omitempty"`
}

const reportTopAssets = 5

func (s *Store) BuildReport(ctx context.Context, from, to, now time.Time) (ReportData, error) {
	d := ReportData{NewVulns: map[model.Severity]int{}, FixedVulns: map[model.Severity]int{},
		TopAssets: []ReportAsset{}, OfflineAgents: []ReportAgent{}, OfflineProbes: []string{}}
	var err error
	if d.Metrics, err = s.DutyMetrics(ctx, from, to, now); err != nil {
		return d, err
	}
	for _, q := range []struct {
		col string
		dst map[model.Severity]int
	}{{"first_seen", d.NewVulns}, {"fixed_at", d.FixedVulns}} {
		rows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM vulns WHERE `+q.col+` >= ? AND `+q.col+` < ? GROUP BY severity`,
			from.UTC(), to.UTC())
		if err != nil {
			return d, err
		}
		for rows.Next() {
			var sev model.Severity
			var n int
			if err := rows.Scan(&sev, &n); err != nil {
				rows.Close()
				return d, err
			}
			q.dst[sev] = n
		}
		rows.Close()
	}
	st, err := s.Stats(ctx)
	if err != nil {
		return d, err
	}
	d.OpenIncidents, d.OpenAlerts, d.OpenVulns = st.OpenIncidents, st.OpenAlerts, st.OpenVulns

	assets, err := s.ListAssets(ctx)
	if err != nil {
		return d, err
	}
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].Risk > assets[j].Risk })
	for _, a := range assets {
		if a.Risk <= 0 || len(d.TopAssets) >= reportTopAssets {
			break
		}
		name := a.Name
		if name == "" {
			name = a.AgentHostname
		}
		if name == "" {
			name = a.Hostname
		}
		d.TopAssets = append(d.TopAssets, ReportAsset{IP: a.IP, Name: name, Owner: a.Owner, Risk: a.Risk, Reasons: a.RiskReasons})
	}

	agents, err := s.ListAgents(ctx)
	if err != nil {
		return d, err
	}
	for _, a := range agents {
		if a.Status == model.AgentOffline {
			d.OfflineAgents = append(d.OfflineAgents, ReportAgent{ID: a.ID, Hostname: a.Hostname, LastSeen: a.LastSeen})
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM nodes WHERE kind = ? AND status = ? AND health = ? ORDER BY id`,
		model.NodeProbe, model.NodeActive, probeOffline)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return d, err
		}
		d.OfflineProbes = append(d.OfflineProbes, id)
	}
	return d, rows.Err()
}

// InsertReport 保存报表；同类型同周期已有报表时不保存，created 为 false（多实例只有一个实例生成并推送）。
func (s *Store) InsertReport(ctx context.Context, kind string, from, to time.Time, data ReportData) (r Report, created bool, err error) {
	raw, _ := json.Marshal(data)
	r = Report{Kind: kind, PeriodStart: from.UTC(), PeriodEnd: to.UTC(), CreatedAt: time.Now().UTC(), Data: &data}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO reports (kind, period_start, period_end, data, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (kind, period_start) DO NOTHING RETURNING id`,
		r.Kind, r.PeriodStart, r.PeriodEnd, string(raw), r.CreatedAt).Scan(&r.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

func (s *Store) HasReport(ctx context.Context, kind string, from time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports WHERE kind = ? AND period_start = ?`, kind, from.UTC()).Scan(&n)
	return n > 0, err
}

// ListReports 返回报表列表（不含内容）；kind 为空时返回全部类型。
func (s *Store) ListReports(ctx context.Context, kind string, limit int) ([]Report, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, period_start, period_end, created_at FROM reports
		WHERE ? = '' OR kind = ? ORDER BY period_start DESC, id DESC LIMIT ?`, kind, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		var r Report
		if err := rows.Scan(&r.ID, &r.Kind, &r.PeriodStart, &r.PeriodEnd, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.PeriodStart, r.PeriodEnd, r.CreatedAt = r.PeriodStart.UTC(), r.PeriodEnd.UTC(), r.CreatedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetReport(ctx context.Context, id int64) (Report, error) {
	var r Report
	var raw string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, kind, period_start, period_end, created_at, data FROM reports WHERE id = ?`, id).
		Scan(&r.ID, &r.Kind, &r.PeriodStart, &r.PeriodEnd, &r.CreatedAt, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	} else if err != nil {
		return r, err
	}
	r.PeriodStart, r.PeriodEnd, r.CreatedAt = r.PeriodStart.UTC(), r.PeriodEnd.UTC(), r.CreatedAt.UTC()
	var d ReportData
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return r, err
	}
	r.Data = &d
	return r, nil
}
