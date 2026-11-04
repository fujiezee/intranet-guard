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

// 探针健康：nodes.health 记录当前状态，状态变化时告警或自动确认告警，每次变化只处理一次。
const (
	probeHealthy   = ""
	probeOffline   = "offline"
	probeIDSSilent = "ids_silent"
)

// TouchProbe 记录探针最近一次通信时间。
func (s *Store) TouchProbe(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET last_seen = ? WHERE kind = ? AND id = ?`,
		at.UnixMilli(), model.NodeProbe, id)
	return err
}

// CheckProbeHealth 把超过 after 没有通信的探针标记为离线、在线但超过 after 没有 IDS 上报的标记为流量检测中断，
// 并告警；恢复的探针自动确认对应告警。返回本次状态变化的探针数。
func (s *Store) CheckProbeHealth(ctx context.Context, now time.Time, after time.Duration) (int, error) {
	if err := s.backfillIDSSeen(ctx); err != nil {
		return 0, err
	}
	cutoff := now.Add(-after).UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	type probe struct {
		id string
		at int64
	}
	transition := func(q string, args ...any) ([]probe, error) {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []probe
		for rows.Next() {
			var p probe
			if err := rows.Scan(&p.id, &p.at); err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		return out, rows.Err()
	}
	raise := func(ps []probe, mk func(ip, id string, at time.Time) alert.DedupAlert) error {
		for _, p := range ps {
			ip, err := probeIP(ctx, tx, p.id)
			if err != nil {
				return err
			}
			a := mk(ip, p.id, time.UnixMilli(p.at))
			if err := insertAlertRow(ctx, tx, a.Alert, a.DedupKey, now); err != nil {
				return err
			}
		}
		return nil
	}
	resolve := func(ps []probe, keys ...func(string) string) error {
		note := "已自动恢复 " + now.Local().Format("2006-01-02 15:04:05")
		for _, p := range ps {
			for _, key := range keys {
				if _, err := tx.ExecContext(ctx, `
					UPDATE alerts SET status = ?, acked_by = ?, resolution_note = ?, updated_at = ? WHERE dedup_key = ? AND status = ?`,
					model.AlertAcked, "system", note, now, key(p.id), model.AlertOpen); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// 顺序有意为之：刚恢复通信的探针本轮不检查 IDS，留一分钟让积压的事件上报。
	offline, err := transition(`
		UPDATE nodes SET health = ? WHERE kind = ? AND status = ? AND health <> ? AND last_seen > 0 AND last_seen < ?
		RETURNING id, last_seen`,
		probeOffline, model.NodeProbe, model.NodeActive, probeOffline, cutoff)
	if err != nil {
		return 0, err
	}
	if err := raise(offline, alert.ProbeOffline); err != nil {
		return 0, err
	}
	silent, err := transition(`
		UPDATE nodes SET health = ? WHERE kind = ? AND status = ? AND health = ? AND ids_seen > 0 AND ids_seen < ?
		RETURNING id, ids_seen`,
		probeIDSSilent, model.NodeProbe, model.NodeActive, probeHealthy, cutoff)
	if err != nil {
		return 0, err
	}
	if err := raise(silent, alert.IDSSilent); err != nil {
		return 0, err
	}
	idsBack, err := transition(`
		UPDATE nodes SET health = ? WHERE kind = ? AND health = ? AND ids_seen >= ? RETURNING id, ids_seen`,
		probeHealthy, model.NodeProbe, probeIDSSilent, cutoff)
	if err != nil {
		return 0, err
	}
	if err := resolve(idsBack, alert.IDSSilentKey); err != nil {
		return 0, err
	}
	// 离线前可能已处于流量检测中断，两条告警一起确认；IDS 若仍无上报，下一轮会重新告警。
	online, err := transition(`
		UPDATE nodes SET health = ? WHERE kind = ? AND health = ? AND last_seen >= ? RETURNING id, last_seen`,
		probeHealthy, model.NodeProbe, probeOffline, cutoff)
	if err != nil {
		return 0, err
	}
	if err := resolve(online, alert.ProbeOfflineKey, alert.IDSSilentKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(offline) + len(silent) + len(idsBack) + len(online), nil
}

// backfillIDSSeen 为 ids_seen 未知（0）的探针按事件存储中最新的 IDS 事件回填；从未上报过的记为 -1，不检查 IDS。
// 在事务之外执行：事件存储可能与主库共用 SQLite 的唯一连接。
func (s *Store) backfillIDSSeen(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM nodes WHERE kind = ? AND ids_seen = 0`, model.NodeProbe)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		evs, err := s.events.ListIDSEvents(ctx, IDSFilter{ProbeID: id, Limit: 1})
		if err != nil {
			return err
		}
		seen := int64(-1)
		if len(evs) > 0 {
			seen = evs[0].Time.UnixMilli()
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE nodes SET ids_seen = ? WHERE kind = ? AND id = ? AND ids_seen = 0`,
			seen, model.NodeProbe, id); err != nil {
			return err
		}
	}
	return nil
}

// probeIP 返回告警关联的探针地址：探针上报的本机地址中优先资产库已有的，没有地址时用探针 ID。
func probeIP(ctx context.Context, q querier, id string) (string, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT probe_ips FROM honeypots WHERE probe_id = ?`, id).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	a := model.AgentInfo{Hostname: id}
	_ = json.Unmarshal([]byte(raw), &a.IPs)
	return primaryIP(ctx, q, a)
}
