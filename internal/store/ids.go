package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// SaveIDSReport 保存探针上报的 IDS 事件，未被抑制的高 / 中优先级事件生成告警。
func (s *Store) SaveIDSReport(ctx context.Context, rep model.IDSReport) error {
	if len(rep.Events) > MaxEventsPerReport {
		return ErrTooManyEvents
	}
	suppressed, err := loadSuppressions(ctx, s.db)
	if err != nil {
		return err
	}
	for i, ev := range rep.Events {
		rep.Events[i].Suppressed = suppressed[suppressKey{ev.SignatureID, ""}] || suppressed[suppressKey{ev.SignatureID, ev.SrcIP}]
	}
	// 与 SaveAgentReport 相同：事件先进事件存储，告警在主库事务中生成。
	if err := s.events.InsertIDSEvents(ctx, rep.ProbeID, rep.Events); err != nil {
		return err
	}
	intel, err := s.intelSnapshot(ctx) // 事务之前读取：SQLite 只有一个连接
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, ev := range rep.Events {
		if ev.Suppressed {
			continue
		}
		ip, err := idsAssetIP(ctx, tx, ev)
		if err != nil {
			return err
		}
		if al, ok := alert.IDS(ip, ev); ok {
			if err := insertDedupAlert(ctx, tx, al, now); err != nil {
				return err
			}
		}
		for _, peer := range []string{ev.SrcIP, ev.DestIP} {
			if peer == ip {
				continue
			}
			if a, err := netip.ParseAddr(peer); err == nil {
				if ind, ok := intel.MatchIP(a.Unmap()); ok {
					if err := insertDedupAlert(ctx, tx, alert.IntelIDS(ip, peer, ev, ind), now); err != nil {
						return err
					}
				}
			}
		}
	}
	return tx.Commit()
}

// idsAssetIP 选出告警要关联的内网资产：优先资产库中已有的目的 / 源地址，其次内网地址。
func idsAssetIP(ctx context.Context, tx *Tx, ev model.IDSEvent) (string, error) {
	for _, ip := range []string{ev.DestIP, ev.SrcIP} {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM assets WHERE ip = ?`, ip).Scan(&one)
		if err == nil {
			return ip, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	for _, ip := range []string{ev.DestIP, ev.SrcIP} {
		if a, err := netip.ParseAddr(ip); err == nil && a.IsPrivate() {
			return ip, nil
		}
	}
	return ev.DestIP, nil
}

type suppressKey struct {
	sid int64
	src string
}

func loadSuppressions(ctx context.Context, db *DB) (map[suppressKey]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT signature_id, src_ip FROM ids_suppressions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[suppressKey]bool{}
	for rows.Next() {
		var k suppressKey
		if err := rows.Scan(&k.sid, &k.src); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

func (s *Store) CreateSuppression(ctx context.Context, sp model.IDSSuppression) (model.IDSSuppression, error) {
	sp.CreatedAt = time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO ids_suppressions (signature_id, src_ip, note, created_by, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id`,
		sp.SignatureID, sp.SrcIP, sp.Note, sp.CreatedBy, sp.CreatedAt).Scan(&sp.ID)
	if err != nil && isUniqueViolation(err) {
		return sp, ErrConflict
	}
	return sp, err
}

func (s *Store) ListSuppressions(ctx context.Context) ([]model.IDSSuppression, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, signature_id, src_ip, note, created_by, created_at FROM ids_suppressions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.IDSSuppression{}
	for rows.Next() {
		var sp model.IDSSuppression
		if err := rows.Scan(&sp.ID, &sp.SignatureID, &sp.SrcIP, &sp.Note, &sp.CreatedBy, &sp.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSuppression(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ids_suppressions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
