package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// IncidentWindow：同一主机的入侵类告警与该主机未结事件的最后一条告警相隔不超过此时长时并入同一事件。
const IncidentWindow = 2 * time.Hour

var severityRank = map[model.Severity]int{model.SeverityLow: 0, model.SeverityMedium: 1, model.SeverityHigh: 2}

// attachToIncident 把入侵类告警并入该主机的未结事件，没有时开启新事件。
// 事件涉及 3 个及以上攻击阶段时升级为高危：多阶段几乎可以确定是真实入侵。
func attachToIncident(ctx context.Context, tx *Tx, alertID int64, a model.Alert, at time.Time) error {
	stage, ok, canOpen := alert.IncidentStage(a.Type)
	if !ok || a.IP == "" {
		return nil
	}
	// 低级的可疑命令只来自执行本管理中心的一键安装命令（见 detectHostAlerts），不是攻击阶段
	if a.Type == model.AlertSuspiciousCommand && a.Severity == model.SeverityLow {
		return nil
	}
	var id int64
	var sev model.Severity
	var stages string
	err := tx.QueryRowContext(ctx, `
		SELECT id, severity, stages FROM incidents
		WHERE ip = ? AND status IN (?, ?) AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1`,
		a.IP, model.IncidentOpen, model.IncidentInvestigating, at.Add(-IncidentWindow)).Scan(&id, &sev, &stages)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !canOpen {
			return nil
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO incidents (ip, title, severity, status, stages, alert_count, first_seen, last_seen, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?) RETURNING id`,
			a.IP, a.IP+"："+alert.RuleName(a.Type), a.Severity, model.IncidentOpen, stage.Key, at, at, at, at).Scan(&id)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		merged := mergeStages(stages, stage.Key)
		newSev := sev
		if severityRank[a.Severity] > severityRank[newSev] {
			newSev = a.Severity
		}
		if len(merged) >= 3 {
			newSev = model.SeverityHigh
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE incidents SET severity = ?, stages = ?, alert_count = alert_count + 1, last_seen = ?, updated_at = ? WHERE id = ?`,
			newSev, strings.Join(merged, ","), at, at, id); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE alerts SET incident_id = ? WHERE id = ?`, id, alertID)
	return err
}

// mergeStages 合并阶段并按攻击链顺序排列。
func mergeStages(existing, add string) []string {
	return parseStages(existing + "," + add)
}

// parseStages 解析逗号分隔的阶段列表，去重、去空并按攻击链顺序排列。
func parseStages(list string) []string {
	set := map[string]bool{}
	for _, s := range strings.Split(list, ",") {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := alert.StageByKey(out[i])
		b, _ := alert.StageByKey(out[j])
		return a.Order < b.Order
	})
	return out
}

const incidentColumns = `id, ip, title, severity, status, assignee, stages, alert_count, first_seen, last_seen, created_at, updated_at`

func scanIncident(row interface{ Scan(...any) error }) (model.Incident, error) {
	var in model.Incident
	var stages string
	err := row.Scan(&in.ID, &in.IP, &in.Title, &in.Severity, &in.Status, &in.Assignee, &stages, &in.AlertCount,
		&in.FirstSeen, &in.LastSeen, &in.CreatedAt, &in.UpdatedAt)
	in.Stages = parseStages(stages)
	return in, err
}

func (s *Store) ListIncidents(ctx context.Context, status model.IncidentStatus) ([]model.Incident, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents
		WHERE ? = '' OR status = ? ORDER BY last_seen DESC LIMIT 500`, status, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Incident{}
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, id int64) (model.Incident, error) {
	in, err := scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return in, ErrNotFound
	}
	return in, err
}

func (s *Store) IncidentAlerts(ctx context.Context, id int64) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, severity, ip, port, message, status, acked_by, resolution, resolution_note, created_at, updated_at
		FROM alerts WHERE incident_id = ? ORDER BY created_at, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Alert{}
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.IP, &a.Port, &a.Message, &a.Status, &a.AckedBy,
			&a.Resolution, &a.ResolutionNote, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.IncidentID = id
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateIncident 修改状态或负责人（空字符串表示不修改）。结案时一并确认其下未处理的告警。
func (s *Store) UpdateIncident(ctx context.Context, id int64, status model.IncidentStatus, assignee *string, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE incidents SET status = CASE WHEN ? = '' THEN status ELSE ? END,
			assignee = CASE WHEN ? THEN ? ELSE assignee END, updated_at = ? WHERE id = ?`,
		status, status, assignee != nil, deref(assignee), now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if status == model.IncidentResolved || status == model.IncidentFalsePositive {
		resolution := ""
		if status == model.IncidentFalsePositive {
			resolution = model.ResolutionFalsePositive
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE alerts SET status = ?, acked_by = ?, resolution = CASE WHEN ? = '' THEN resolution ELSE ? END, updated_at = ?
			WHERE incident_id = ? AND status = ?`,
			model.AlertAcked, by, resolution, resolution, now, id, model.AlertOpen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Store) AddIncidentNote(ctx context.Context, id int64, author, body string) (model.IncidentNote, error) {
	n := model.IncidentNote{Author: author, Body: body, CreatedAt: time.Now().UTC()}
	if _, err := s.GetIncident(ctx, id); err != nil {
		return n, err
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO incident_notes (incident_id, author, body, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
		id, author, body, n.CreatedAt).Scan(&n.ID)
	return n, err
}

func (s *Store) IncidentNotes(ctx context.Context, id int64) ([]model.IncidentNote, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, author, body, created_at FROM incident_notes WHERE incident_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.IncidentNote{}
	for rows.Next() {
		var n model.IncidentNote
		if err := rows.Scan(&n.ID, &n.Author, &n.Body, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AgentIDsForIP 返回上报过该地址的 Agent，用于在事件时间线中附上该主机的审计记录。
func (s *Store) AgentIDsForIP(ctx context.Context, ip string) ([]string, error) {
	agents, err := s.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range agents {
		for _, x := range a.IPs {
			if x == ip {
				out = append(out, a.ID)
			}
		}
	}
	return out, nil
}
