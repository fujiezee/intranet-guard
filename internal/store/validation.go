package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"safe/internal/model"
)

// ValidationApprovalTTL：超过这个时间没有批准的验证任务失效，避免很久以前的申请被批准后突然执行。
const ValidationApprovalTTL = 24 * time.Hour

var ErrScopeExists = errors.New("scope already exists")

func (s *Store) ListValidationScopes(ctx context.Context) ([]model.ValidationScope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, cidr, note, created_by, created_at FROM validation_scopes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ValidationScope{}
	for rows.Next() {
		var v model.ValidationScope
		if err := rows.Scan(&v.ID, &v.CIDR, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) AddValidationScope(ctx context.Context, v model.ValidationScope) (model.ValidationScope, error) {
	v.CreatedAt = time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO validation_scopes (cidr, note, created_by, created_at) VALUES (?, ?, ?, ?) RETURNING id`,
		v.CIDR, v.Note, v.CreatedBy, v.CreatedAt).Scan(&v.ID)
	if err != nil && isUniqueViolation(err) {
		return v, ErrScopeExists
	}
	return v, err
}

func (s *Store) DeleteValidationScope(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM validation_scopes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateValidationRun(ctx context.Context, r model.ValidationRun) (model.ValidationRun, error) {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	r.ID = "val-" + hex.EncodeToString(b)
	r.Status = model.ValAwaitingApproval
	r.CreatedAt = time.Now().UTC()
	targets, _ := json.Marshal(r.Targets)
	ports, _ := json.Marshal(r.Ports)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO validation_runs (id, name, probe_id, targets, ports, weak_password, status, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.ProbeID, string(targets), string(ports), r.WeakPassword, r.Status, r.CreatedBy, r.CreatedAt)
	return r, err
}

const validationColumns = `r.id, r.name, r.probe_id, r.targets, r.ports, r.weak_password, r.status, r.task_id, r.created_by,
	r.approved_by, r.created_at, r.started_at, COALESCE(t.status, ''), COALESCE(t.error, '')`

// 只保存“等待批准 / 已开始”，开始之后的状态来自扫描任务，不必同步两份。
func scanValidationRun(row interface{ Scan(...any) error }) (model.ValidationRun, error) {
	var r model.ValidationRun
	var targets, ports, stored string
	var taskStatus model.TaskStatus
	var started sql.NullTime
	err := row.Scan(&r.ID, &r.Name, &r.ProbeID, &targets, &ports, &r.WeakPassword, &stored, &r.TaskID, &r.CreatedBy,
		&r.ApprovedBy, &r.CreatedAt, &started, &taskStatus, &r.Error)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(targets), &r.Targets)
	_ = json.Unmarshal([]byte(ports), &r.Ports)
	if started.Valid {
		r.StartedAt = &started.Time
	}
	switch {
	case stored == model.ValAwaitingApproval && time.Since(r.CreatedAt) > ValidationApprovalTTL:
		r.Status = model.ValExpired
	case stored == model.ValAwaitingApproval:
		r.Status = model.ValAwaitingApproval
	case taskStatus == model.TaskDone:
		r.Status = model.ValDone
	case taskStatus == model.TaskFailed:
		r.Status = model.ValFailed
	default:
		r.Status = model.ValRunning
	}
	return r, nil
}

func (s *Store) GetValidationRun(ctx context.Context, id string) (model.ValidationRun, error) {
	r, err := scanValidationRun(s.db.QueryRowContext(ctx, `
		SELECT `+validationColumns+` FROM validation_runs r LEFT JOIN tasks t ON t.id = r.task_id WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

func (s *Store) ListValidationRuns(ctx context.Context, limit int) ([]model.ValidationRun, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+validationColumns+` FROM validation_runs r LEFT JOIN tasks t ON t.id = r.task_id
		ORDER BY r.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ValidationRun{}
	for rows.Next() {
		r, err := scanValidationRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StartValidationRun 批准并下发验证任务。弱口令检测会产生真实的登录失败，需要另一位管理员批准；
// 系统只有一位管理员时由其本人确认，操作留在审计日志中。
func (s *Store) StartValidationRun(ctx context.Context, id, by, taskID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var createdBy, probeID, targets, ports string
	var weak bool
	err = tx.QueryRowContext(ctx, `
		SELECT created_by, probe_id, targets, ports, weak_password FROM validation_runs WHERE id = ? AND status = ? AND created_at > ?`,
		id, model.ValAwaitingApproval, time.Now().UTC().Add(-ValidationApprovalTTL)).Scan(&createdBy, &probeID, &targets, &ports, &weak)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if weak && createdBy == by {
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, model.RoleAdmin).Scan(&admins); err != nil {
			return err
		}
		if admins > 1 {
			return ErrSelfApproval
		}
	}
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE validation_runs SET status = ?, task_id = ?, approved_by = ?, started_at = ? WHERE id = ? AND status = ?`,
		model.ValRunning, taskID, by, now, id, model.ValAwaitingApproval)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tasks (id, probe_id, targets, ports, baseline, kind, weak_password, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, FALSE, ?, ?, ?, ?, ?)`,
		taskID, probeID, targets, ports, model.TaskVuln, weak, model.TaskPending, now, now); err != nil {
		return err
	}
	return tx.Commit()
}
