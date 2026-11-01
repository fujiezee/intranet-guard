package store

import (
	"context"
	"time"

	"safe/internal/model"
)

func insertAlert(ctx context.Context, tx *Tx, a model.Alert, at time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (type, severity, ip, port, message, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Type, a.Severity, a.IP, a.Port, a.Message, model.AlertOpen, at, at)
	return err
}

// ListAlerts 返回最近的告警；status 为空时返回全部状态。
func (s *Store) ListAlerts(ctx context.Context, status model.AlertStatus, limit int) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, severity, ip, port, message, status, acked_by, created_at, updated_at
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
			&a.AckedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (s *Store) AckAlert(ctx context.Context, id int64, by string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = ?, acked_by = ?, updated_at = ? WHERE id = ?`,
		model.AlertAcked, by, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type Stats struct {
	Assets       int            `json:"assets"`
	OpenPorts    int            `json:"open_ports"`
	RunningTasks int            `json:"running_tasks"`
	OpenAlerts   map[string]int `json:"open_alerts"` // 按严重程度
	OpenVulns    map[string]int `json:"open_vulns"`  // 按严重程度
	TopServices  []ServiceCount `json:"top_services"`
}

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	st := Stats{OpenAlerts: map[string]int{}, OpenVulns: map[string]int{}, TopServices: []ServiceCount{}}
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
