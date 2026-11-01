package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"safe/internal/model"
	"safe/internal/simulate"
)

func insertAlert(ctx context.Context, tx *Tx, a model.Alert, at time.Time) error {
	return insertAlertRow(ctx, tx, a, "", at)
}

// insertAlertRow 是所有告警写入的唯一入口。告警内容中带有已登记的自检编号时，
// 告警直接以"自检"结果关闭（不推送、不计入未处理），并把对应自检标记为通过。
func insertAlertRow(ctx context.Context, tx *Tx, a model.Alert, dedupKey string, at time.Time) error {
	status, ackedBy, resolution := model.AlertOpen, "", ""
	var simID string
	var simStarted sql.NullTime
	var simStatus model.SimulationStatus
	if id := simulate.IDPattern.FindString(a.Message); id != "" {
		err := tx.QueryRowContext(ctx, `SELECT status, started_at FROM simulations WHERE id = ?`, id).Scan(&simStatus, &simStarted)
		if err == nil {
			simID = id
			status, ackedBy, resolution = model.AlertAcked, "攻击模拟自检", model.ResolutionSimulation
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	var alertID int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO alerts (type, severity, ip, port, message, status, acked_by, resolution, dedup_key, notified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?, ?) RETURNING id`,
		a.Type, a.Severity, a.IP, a.Port, a.Message, status, ackedBy, resolution, dedupKey, at, at).Scan(&alertID)
	if err != nil {
		return err
	}
	if simID == "" {
		if err := attachToIncident(ctx, tx, alertID, a, at); err != nil {
			return err
		}
	}
	if simID == "" || simStatus != model.SimRunning {
		return nil
	}
	var latency int64
	if simStarted.Valid {
		latency = at.Sub(simStarted.Time).Milliseconds()
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE simulations SET status = ?, alert_id = ?, latency_ms = ?, finished_at = ?
		WHERE id = ? AND status = ?`,
		model.SimPassed, alertID, latency, at, simID, model.SimRunning)
	return err
}

// ListAlerts 返回最近的告警；status 为空时返回全部状态。
func (s *Store) ListAlerts(ctx context.Context, status model.AlertStatus, limit int) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, severity, ip, port, message, status, acked_by, resolution, resolution_note, incident_id, created_at, updated_at
		FROM alerts WHERE ? = '' OR status = ?
		ORDER BY id DESC LIMIT ?`, status, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := []model.Alert{}
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.IP, &a.Port, &a.Message, &a.Status,
			&a.AckedBy, &a.Resolution, &a.ResolutionNote, &a.IncidentID, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// AckAlert 确认告警；falsePositive 为 true 时记为误报及原因，用于统计误报率和调优规则。
func (s *Store) AckAlert(ctx context.Context, id int64, by string, falsePositive bool, note string) error {
	resolution := ""
	if falsePositive {
		resolution = model.ResolutionFalsePositive
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE alerts SET status = ?, acked_by = ?, resolution = ?, resolution_note = ?, updated_at = ? WHERE id = ?`,
		model.AlertAcked, by, resolution, note, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type Stats struct {
	Assets        int            `json:"assets"`
	OpenPorts     int            `json:"open_ports"`
	RunningTasks  int            `json:"running_tasks"`
	OpenAlerts    map[string]int `json:"open_alerts"`    // 按严重程度
	OpenVulns     map[string]int `json:"open_vulns"`     // 按严重程度
	OpenIncidents map[string]int `json:"open_incidents"` // 未结事件，按严重程度
	TopServices   []ServiceCount `json:"top_services"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	st := Stats{OpenAlerts: map[string]int{}, OpenVulns: map[string]int{}, OpenIncidents: map[string]int{}, TopServices: []ServiceCount{}}
	err := s.db.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM ports),
		       (SELECT COUNT(*) FROM tasks WHERE status IN (?, ?))`,
		model.TaskPending, model.TaskRunning).Scan(&st.Assets, &st.OpenPorts, &st.RunningTasks)
	if err != nil {
		return st, err
	}

	for _, q := range []struct {
		sql    string
		status string
		dst    map[string]int
	}{
		{`SELECT severity, COUNT(*) FROM alerts WHERE status = ? GROUP BY severity`, string(model.AlertOpen), st.OpenAlerts},
		{`SELECT severity, COUNT(*) FROM vulns WHERE status = ? GROUP BY severity`, string(model.VulnOpen), st.OpenVulns},
		{`SELECT severity, COUNT(*) FROM incidents WHERE status <> ? AND status <> 'false_positive' GROUP BY severity`, string(model.IncidentResolved), st.OpenIncidents},
	} {
		rows, err := s.db.QueryContext(ctx, q.sql, q.status)
		if err != nil {
			return st, err
		}
		for rows.Next() {
			var sev string
			var n int
			if err := rows.Scan(&sev, &n); err != nil {
				rows.Close()
				return st, err
			}
			q.dst[sev] = n
		}
		rows.Close()
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT CASE WHEN service = '' THEN 'unknown' ELSE service END AS svc, COUNT(*) AS n
		FROM ports GROUP BY svc ORDER BY n DESC LIMIT 10`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var sc ServiceCount
		if err := rows.Scan(&sc.Service, &sc.Count); err != nil {
			return st, err
		}
		st.TopServices = append(st.TopServices, sc)
	}
	return st, rows.Err()
}
