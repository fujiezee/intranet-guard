package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// HoneypotInfo 是某个探针的蜜罐配置及运行状态。
type HoneypotInfo struct {
	ProbeID  string               `json:"probe_id"`
	Config   model.HoneypotConfig `json:"config"`
	ProbeIPs []string             `json:"probe_ips"`
	Status   map[int]string       `json:"status"` // 端口 → listening 或错误
	SeenAt   *time.Time           `json:"seen_at,omitempty"`
}

func (s *Store) SetHoneypot(ctx context.Context, probeID string, cfg model.HoneypotConfig) error {
	services, _ := json.Marshal(cfg.Services)
	ignore, _ := json.Marshal(cfg.IgnoreSources)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO honeypots (probe_id, enabled, services, ignore_sources, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(probe_id) DO UPDATE SET enabled = excluded.enabled, services = excluded.services,
			ignore_sources = excluded.ignore_sources, updated_at = excluded.updated_at`,
		probeID, cfg.Enabled, string(services), string(ignore), time.Now().UTC())
	return err
}

// ProbeConfig 记录探针上报的地址和监听状态，返回它应当运行的蜜罐配置（未配置时为停用）。
func (s *Store) ProbeConfig(ctx context.Context, probeID string, ips []string, status map[int]string) (model.HoneypotConfig, error) {
	ipsJSON, _ := json.Marshal(ips)
	stJSON, _ := json.Marshal(status)
	if _, err := s.db.ExecContext(ctx, `UPDATE honeypots SET probe_ips = ?, status = ?, seen_at = ? WHERE probe_id = ?`,
		string(ipsJSON), string(stJSON), time.Now().UTC(), probeID); err != nil {
		return model.HoneypotConfig{}, err
	}
	info, err := s.getHoneypot(ctx, probeID)
	if errors.Is(err, ErrNotFound) {
		return model.HoneypotConfig{Services: []model.HoneypotService{}, IgnoreSources: []string{}}, nil
	}
	return info.Config, err
}

func (s *Store) getHoneypot(ctx context.Context, probeID string) (HoneypotInfo, error) {
	all, err := s.ListHoneypots(ctx)
	if err != nil {
		return HoneypotInfo{}, err
	}
	for _, h := range all {
		if h.ProbeID == probeID {
			return h, nil
		}
	}
	return HoneypotInfo{}, ErrNotFound
}

func (s *Store) ListHoneypots(ctx context.Context) ([]HoneypotInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT probe_id, enabled, services, ignore_sources, probe_ips, status, seen_at FROM honeypots ORDER BY probe_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HoneypotInfo{}
	for rows.Next() {
		var h HoneypotInfo
		var services, ignore, ips, status string
		var seen sql.NullTime
		if err := rows.Scan(&h.ProbeID, &h.Config.Enabled, &services, &ignore, &ips, &status, &seen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(services), &h.Config.Services)
		_ = json.Unmarshal([]byte(ignore), &h.Config.IgnoreSources)
		_ = json.Unmarshal([]byte(ips), &h.ProbeIPs)
		_ = json.Unmarshal([]byte(status), &h.Status)
		if seen.Valid {
			h.SeenAt = &seen.Time
		}
		if h.Config.IgnoreSources == nil {
			h.Config.IgnoreSources = []string{}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// honeypotIPs 返回启用了蜜罐的探针地址：这些地址上的端口是伪装的，不产生资产变化告警。
func honeypotIPs(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT probe_ips FROM honeypots WHERE enabled = ?`, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ips string
		if err := rows.Scan(&ips); err != nil {
			return nil, err
		}
		var list []string
		_ = json.Unmarshal([]byte(ips), &list)
		for _, ip := range list {
			out[ip] = true
		}
	}
	return out, rows.Err()
}

// SaveHoneypotEvents 记录蜜罐访问并告警。告警关联到访问来源——内网里访问蜜罐的主机很可能已经失陷。
func (s *Store) SaveHoneypotEvents(ctx context.Context, probeID string, events []model.HoneypotEvent) error {
	if len(events) > MaxEventsPerReport {
		return ErrTooManyEvents
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, ev := range events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO honeypot_events (probe_id, ts, service, port, src_ip, src_port, username, password, detail, simulation_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			probeID, ev.Time.UTC(), ev.Service, ev.Port, ev.SrcIP, ev.SrcPort, ev.Username, ev.Password, ev.Detail, ev.SimulationID); err != nil {
			return err
		}
		if err := insertDedupAlert(ctx, tx, alert.Honeypot(probeID, ev), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListHoneypotEvents(ctx context.Context, limit int) ([]model.HoneypotEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, probe_id, ts, service, port, src_ip, src_port, username, password, detail, simulation_id
		FROM honeypot_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.HoneypotEvent{}
	for rows.Next() {
		var e model.HoneypotEvent
		if err := rows.Scan(&e.ID, &e.ProbeID, &e.Time, &e.Service, &e.Port, &e.SrcIP, &e.SrcPort,
			&e.Username, &e.Password, &e.Detail, &e.SimulationID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
