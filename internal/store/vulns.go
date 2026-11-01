package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// saveChecks 按检查结果维护漏洞生命周期，返回需要告警的新发现 / 复发漏洞：
//   - 发现漏洞：新增为 open；之前已修复的重新打开；已忽略的只更新最后发现时间，不再告警
//   - 检查通过：之前 open / ignored 的标记为 fixed
func saveChecks(ctx context.Context, tx *Tx, results []model.CheckResult, at time.Time) ([]model.Alert, error) {
	var alerts []model.Alert
	for _, r := range results {
		if !r.Vulnerable {
			if err := fixVulns(ctx, tx, r.IP, r.Port, r.CheckID, at); err != nil {
				return nil, err
			}
			continue
		}
		var id int64
		var status model.VulnStatus
		err := tx.QueryRowContext(ctx, `SELECT id, status FROM vulns WHERE ip = ? AND port = ? AND check_id = ?`,
			r.IP, r.Port, r.CheckID).Scan(&id, &status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO vulns (ip, port, check_id, title, severity, detail, status, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				r.IP, r.Port, r.CheckID, r.Title, r.Severity, r.Detail, model.VulnOpen, at, at); err != nil {
				return nil, err
			}
			alerts = append(alerts, alert.Vuln(r, false))
		case err != nil:
			return nil, err
		default:
			newStatus := status
			if status == model.VulnFixed {
				newStatus = model.VulnOpen
				alerts = append(alerts, alert.Vuln(r, true))
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE vulns SET title = ?, severity = ?, detail = ?, status = ?, last_seen = ?, fixed_at = NULL WHERE id = ?`,
				r.Title, r.Severity, r.Detail, newStatus, at, id); err != nil {
				return nil, err
			}
		}
	}
	return alerts, nil
}

// fixVulns 把指定端口上（checkID 为空时为该端口全部）未修复的漏洞标记为已修复。
func fixVulns(ctx context.Context, tx *Tx, ip string, port int, checkID string, at time.Time) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE vulns SET status = ?, fixed_at = ?
		WHERE ip = ? AND port = ? AND (? = '' OR check_id = ?) AND status IN (?, ?)`,
		model.VulnFixed, at, ip, port, checkID, checkID, model.VulnOpen, model.VulnIgnored)
	return err
}

type VulnFilter struct {
	Status   model.VulnStatus
	Severity model.Severity
	IP       string
}

func (s *Store) ListVulns(ctx context.Context, f VulnFilter) ([]model.Vuln, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ip, port, check_id, title, severity, detail, status, first_seen, last_seen, fixed_at FROM vulns
		WHERE (? = '' OR status = ?) AND (? = '' OR severity = ?) AND (? = '' OR ip = ?)
		ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, last_seen DESC
		LIMIT 5000`,
		f.Status, f.Status, f.Severity, f.Severity, f.IP, f.IP)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Vuln{}
	for rows.Next() {
		var v model.Vuln
		var fixed sql.NullTime
		if err := rows.Scan(&v.ID, &v.IP, &v.Port, &v.CheckID, &v.Title, &v.Severity, &v.Detail, &v.Status,
			&v.FirstSeen, &v.LastSeen, &fixed); err != nil {
			return nil, err
		}
		if fixed.Valid {
			v.FixedAt = &fixed.Time
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetVulnStatus 人工忽略漏洞，或取消忽略重新打开。已修复状态只能由复查自动设置。
func (s *Store) SetVulnStatus(ctx context.Context, id int64, status model.VulnStatus) error {
	from := model.VulnOpen
	if status == model.VulnOpen {
		from = model.VulnIgnored
	}
	res, err := s.db.ExecContext(ctx, `UPDATE vulns SET status = ? WHERE id = ? AND status = ?`, status, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
