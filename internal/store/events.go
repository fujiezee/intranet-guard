package store

import (
	"context"
	"time"

	"safe/internal/model"
)

// EventStore 存放海量审计事件（主机事件、IDS 事件）。默认存在主库（SQLite / PostgreSQL）中，
// 大规模部署可换成 ClickHouse（internal/chstore）。业务数据（资产、告警、漏洞等）始终在主库。
type EventStore interface {
	InsertHostEvents(ctx context.Context, agentID string, events []model.HostEvent) error
	CountLoginFailures(ctx context.Context, agentID, srcIP string, from, to time.Time) (int, error)
	// CountLoginTargets 返回某来源在时间范围内成功登录过的不同主机数。
	CountLoginTargets(ctx context.Context, srcIP string, from, to time.Time) (int, error)
	ListHostEvents(ctx context.Context, f EventFilter) ([]model.HostEvent, error)
	InsertIDSEvents(ctx context.Context, probeID string, events []model.IDSEvent) error
	ListIDSEvents(ctx context.Context, f IDSFilter) ([]model.IDSEvent, error)
	// Purge 删除早于 before 的事件，返回删除行数。自带过期机制的实现可以直接返回 0。
	Purge(ctx context.Context, before time.Time) (int64, error)
}

type EventFilter struct {
	AgentID  string
	Type     model.HostEventType
	SrcIP    string
	From, To time.Time // 为零值时不限
	Limit    int
}

// Bounds 返回时间范围（unix 毫秒），未设置时为全部时间。
func (f EventFilter) Bounds() (int64, int64) {
	from, to := int64(0), int64(1)<<62
	if !f.From.IsZero() {
		from = f.From.UnixMilli()
	}
	if !f.To.IsZero() {
		to = f.To.UnixMilli()
	}
	return from, to
}

type IDSFilter struct {
	ProbeID     string
	SrcIP       string
	DestIP      string
	SignatureID int64
	MaxSeverity int // 只返回优先级 <= 该值的事件；0 表示不限
	Limit       int
}

// UseEventStore 把事件存储切换到 es（例如 ClickHouse）。
func (s *Store) UseEventStore(es EventStore) { s.events = es }

func (s *Store) ListHostEvents(ctx context.Context, f EventFilter) ([]model.HostEvent, error) {
	return s.events.ListHostEvents(ctx, f)
}

func (s *Store) ListIDSEvents(ctx context.Context, f IDSFilter) ([]model.IDSEvent, error) {
	return s.events.ListIDSEvents(ctx, f)
}

func (s *Store) PurgeEvents(ctx context.Context, before time.Time) (int64, error) {
	return s.events.Purge(ctx, before)
}

// sqlEvents 把事件存在主库中。
type sqlEvents struct{ db *DB }

func (e *sqlEvents) InsertHostEvents(ctx context.Context, agentID string, events []model.HostEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, ev := range events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO host_events (agent_id, type, ts, "user", src_ip, path, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			agentID, ev.Type, ev.Time.UnixMilli(), ev.User, ev.SrcIP, ev.Path, ev.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (e *sqlEvents) CountLoginFailures(ctx context.Context, agentID, srcIP string, from, to time.Time) (int, error) {
	var n int
	err := e.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM host_events
		WHERE agent_id = ? AND type = ? AND src_ip = ? AND ts BETWEEN ? AND ?`,
		agentID, model.EventLoginFailed, srcIP, from.UnixMilli(), to.UnixMilli()).Scan(&n)
	return n, err
}

func (e *sqlEvents) CountLoginTargets(ctx context.Context, srcIP string, from, to time.Time) (int, error) {
	var n int
	err := e.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT agent_id) FROM host_events WHERE type = ? AND src_ip = ? AND ts BETWEEN ? AND ?`,
		model.EventLoginSuccess, srcIP, from.UnixMilli(), to.UnixMilli()).Scan(&n)
	return n, err
}

func (e *sqlEvents) ListHostEvents(ctx context.Context, f EventFilter) ([]model.HostEvent, error) {
	from, to := f.Bounds()
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, agent_id, type, ts, "user", src_ip, path, detail FROM host_events
		WHERE (? = '' OR agent_id = ?) AND (? = '' OR type = ?) AND (? = '' OR src_ip = ?) AND ts BETWEEN ? AND ?
		ORDER BY ts DESC, id DESC LIMIT ?`,
		f.AgentID, f.AgentID, f.Type, f.Type, f.SrcIP, f.SrcIP, from, to, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []model.HostEvent{}
	for rows.Next() {
		var ev model.HostEvent
		var ts int64
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.Type, &ts, &ev.User, &ev.SrcIP, &ev.Path, &ev.Detail); err != nil {
			return nil, err
		}
		ev.Time = time.UnixMilli(ts).UTC()
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (e *sqlEvents) InsertIDSEvents(ctx context.Context, probeID string, events []model.IDSEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, ev := range events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ids_events (probe_id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
				signature_id, signature, category, severity, action, suppressed)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			probeID, ev.Time.UnixMilli(), ev.SrcIP, ev.SrcPort, ev.DestIP, ev.DestPort, ev.Proto, ev.AppProto,
			ev.SignatureID, ev.Signature, ev.Category, ev.Severity, ev.Action, ev.Suppressed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (e *sqlEvents) ListIDSEvents(ctx context.Context, f IDSFilter) ([]model.IDSEvent, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, probe_id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
		       signature_id, signature, category, severity, action, suppressed
		FROM ids_events
		WHERE (? = '' OR probe_id = ?) AND (? = '' OR src_ip = ?) AND (? = '' OR dest_ip = ?)
		  AND (? = 0 OR signature_id = ?) AND (? = 0 OR severity <= ?)
		ORDER BY ts DESC, id DESC LIMIT ?`,
		f.ProbeID, f.ProbeID, f.SrcIP, f.SrcIP, f.DestIP, f.DestIP,
		f.SignatureID, f.SignatureID, f.MaxSeverity, f.MaxSeverity, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []model.IDSEvent{}
	for rows.Next() {
		var ev model.IDSEvent
		var ts int64
		if err := rows.Scan(&ev.ID, &ev.ProbeID, &ts, &ev.SrcIP, &ev.SrcPort, &ev.DestIP, &ev.DestPort, &ev.Proto,
			&ev.AppProto, &ev.SignatureID, &ev.Signature, &ev.Category, &ev.Severity, &ev.Action, &ev.Suppressed); err != nil {
			return nil, err
		}
		ev.Time = time.UnixMilli(ts).UTC()
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (e *sqlEvents) Purge(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"host_events", "ids_events"} {
		res, err := e.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE ts < ?`, before.UnixMilli())
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ExportEvents 把主库中的全部主机事件和 IDS 事件分批写入 dst（用于切换到 ClickHouse 时迁移历史事件），
// 返回两类事件的条数。主库中的事件保持不动。
func (s *Store) ExportEvents(ctx context.Context, dst EventStore, batch int) (hosts, ids int, err error) {
	src := &sqlEvents{db: s.db}
	rows, err := src.db.QueryContext(ctx, `SELECT agent_id, type, ts, "user", src_ip, path, detail FROM host_events ORDER BY agent_id, ts, id`)
	if err != nil {
		return 0, 0, err
	}
	var buf []model.HostEvent
	agent := ""
	flushHosts := func() error {
		if len(buf) == 0 {
			return nil
		}
		err := dst.InsertHostEvents(ctx, agent, buf)
		hosts += len(buf)
		buf = buf[:0]
		return err
	}
	for rows.Next() {
		var a string
		var ev model.HostEvent
		var ts int64
		if err := rows.Scan(&a, &ev.Type, &ts, &ev.User, &ev.SrcIP, &ev.Path, &ev.Detail); err != nil {
			rows.Close()
			return hosts, ids, err
		}
		ev.Time = time.UnixMilli(ts).UTC()
		if a != agent || len(buf) >= batch {
			if err := flushHosts(); err != nil {
				rows.Close()
				return hosts, ids, err
			}
			agent = a
		}
		buf = append(buf, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return hosts, ids, err
	}
	if err := flushHosts(); err != nil {
		return hosts, ids, err
	}

	rows, err = src.db.QueryContext(ctx, `
		SELECT probe_id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
		       signature_id, signature, category, severity, action, suppressed
		FROM ids_events ORDER BY probe_id, ts, id`)
	if err != nil {
		return hosts, ids, err
	}
	defer rows.Close()
	var ibuf []model.IDSEvent
	probe := ""
	flushIDS := func() error {
		if len(ibuf) == 0 {
			return nil
		}
		err := dst.InsertIDSEvents(ctx, probe, ibuf)
		ids += len(ibuf)
		ibuf = ibuf[:0]
		return err
	}
	for rows.Next() {
		var p string
		var ev model.IDSEvent
		var ts int64
		if err := rows.Scan(&p, &ts, &ev.SrcIP, &ev.SrcPort, &ev.DestIP, &ev.DestPort, &ev.Proto, &ev.AppProto,
			&ev.SignatureID, &ev.Signature, &ev.Category, &ev.Severity, &ev.Action, &ev.Suppressed); err != nil {
			return hosts, ids, err
		}
		ev.Time = time.UnixMilli(ts).UTC()
		if p != probe || len(ibuf) >= batch {
			if err := flushIDS(); err != nil {
				return hosts, ids, err
			}
			probe = p
		}
		ibuf = append(ibuf, ev)
	}
	if err := rows.Err(); err != nil {
		return hosts, ids, err
	}
	return hosts, ids, flushIDS()
}
