package store

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"safe/internal/model"
)

// FailStaleTasks 把执行超过 cutoff 仍未上报结果的任务标记为失败（通常是探针崩溃或断网），返回任务 ID。
// 之后探针如果仍然上报了结果，SaveReport 照常接收并把任务改为完成。
func (s *Store) FailStaleTasks(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		UPDATE tasks SET status = ?, error = ?, updated_at = ?
		WHERE status = ? AND updated_at < ? RETURNING id`,
		model.TaskFailed, "probe did not report a result in time (crashed or disconnected?)", time.Now().UTC(),
		model.TaskRunning, cutoff.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// --- 告警推送 ---

func (s *Store) CreateChannel(ctx context.Context, c model.NotifyChannel) (model.NotifyChannel, error) {
	c.CreatedAt = time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO notify_channels (name, type, url, secret, min_severity, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		c.Name, c.Type, c.URL, c.Secret, c.MinSeverity, c.Enabled, c.CreatedAt).Scan(&c.ID)
	return c, err
}

// ListChannels 返回全部渠道（含完整 URL 和密钥，供推送使用；对外展示前由调用方脱敏）。
func (s *Store) ListChannels(ctx context.Context) ([]model.NotifyChannel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, url, secret, min_severity, enabled, last_error, last_sent_at, created_at
		FROM notify_channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.NotifyChannel{}
	for rows.Next() {
		var c model.NotifyChannel
		var sent sql.NullTime
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.URL, &c.Secret, &c.MinSeverity, &c.Enabled,
			&c.LastError, &sent, &c.CreatedAt); err != nil {
			return nil, err
		}
		if sent.Valid {
			c.LastSentAt = &sent.Time
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetChannel(ctx context.Context, id int64) (model.NotifyChannel, error) {
	all, err := s.ListChannels(ctx)
	if err != nil {
		return model.NotifyChannel{}, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return model.NotifyChannel{}, ErrNotFound
}

func (s *Store) SetChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	return s.execOne(ctx, `UPDATE notify_channels SET enabled = ? WHERE id = ?`, enabled, id)
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	return s.execOne(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
}

// RecordChannelResult 记录最近一次推送的结果，便于在控制台发现配置错误。
func (s *Store) RecordChannelResult(ctx context.Context, id int64, sendErr error) error {
	if sendErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET last_error = ? WHERE id = ?`, sendErr.Error(), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET last_error = '', last_sent_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

func (s *Store) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkNotified 把告警标记为已推送。
func (s *Store) MarkNotified(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	marks := make([]string, len(ids))
	for i, id := range ids {
		args[i], marks[i] = id, "?"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET notified = TRUE WHERE id IN (`+strings.Join(marks, ",")+`)`, args...)
	return err
}

// ClaimPendingAlerts 领取一批尚未推送的告警，按 ID 升序返回。
//
// 不用"上次推送到的 ID"作游标：并发写入时 ID 较小的告警可能晚于 ID 较大的告警提交，游标会跳过它而漏推。
// 领取带租约：并发的推送方（多实例切换的瞬间）领到互不重叠的告警，不会重复推送；领取后实例宕机、
// 没来得及标记已推送的告警，租约过期后被重新领取，不会漏推。外层 WHERE 重复判断领取条件：
// PostgreSQL 并发更新同一行时会按最新版本重新判断外层条件，已被别人领取的行因此被排除。
func (s *Store) ClaimPendingAlerts(ctx context.Context, limit int, lease time.Duration) ([]model.Alert, error) {
	now := time.Now().UTC()
	expired := now.Add(-lease)
	rows, err := s.db.QueryContext(ctx, `
		UPDATE alerts SET notify_claimed_at = ?
		WHERE id IN (
			SELECT id FROM alerts WHERE NOT notified AND (notify_claimed_at IS NULL OR notify_claimed_at < ?) ORDER BY id LIMIT ?
		) AND NOT notified AND (notify_claimed_at IS NULL OR notify_claimed_at < ?)
		RETURNING id, type, severity, ip, port, message, status, acked_by, resolution, created_at, updated_at`,
		now, expired, limit, expired)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.IP, &a.Port, &a.Message, &a.Status,
			&a.AckedBy, &a.Resolution, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID }) // RETURNING 不保证顺序
	return out, nil
}

// --- 操作审计 ---

func (s *Store) AddAudit(ctx context.Context, e model.AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, username, action, target, detail, client_ip, success) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Time.UTC(), e.Username, e.Action, e.Target, e.Detail, e.ClientIP, e.Success)
	return err
}

type AuditFilter struct {
	Username string
	Action   string
	Limit    int
}

func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]model.AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, username, action, target, detail, client_ip, success FROM audit_log
		WHERE (? = '' OR username = ?) AND (? = '' OR action = ?)
		ORDER BY id DESC LIMIT ?`, f.Username, f.Username, f.Action, f.Action, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.Username, &e.Action, &e.Target, &e.Detail, &e.ClientIP, &e.Success); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
