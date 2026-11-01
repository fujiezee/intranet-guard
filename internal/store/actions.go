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

var (
	ErrSelfApproval    = errors.New("an action cannot be approved by the admin who created it")
	ErrNotRollbackable = errors.New("action cannot be rolled back")
)

// Rollbacks 是可撤销的动作及其撤销动作。
var Rollbacks = map[string]string{
	model.ActBlockIP:    model.ActUnblockIP,
	model.ActQuarantine: model.ActRestoreFile,
	model.ActIsolate:    model.ActRelease,
}

// RequiresApproval：影响最大的动作需要另一位管理员批准。
var RequiresApproval = map[string]bool{model.ActIsolate: true}

const actionColumns = `id, agent_id, type, params, reason, status, result, created_by, approved_by, rollback_of, created_at, updated_at`

func scanAction(row interface{ Scan(...any) error }) (model.ResponseAction, error) {
	var a model.ResponseAction
	var params string
	err := row.Scan(&a.ID, &a.AgentID, &a.Type, &params, &a.Reason, &a.Status, &a.Result, &a.CreatedBy, &a.ApprovedBy,
		&a.RollbackOf, &a.CreatedAt, &a.UpdatedAt)
	_ = json.Unmarshal([]byte(params), &a.Params)
	return a, err
}

func newActionID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "act-" + hex.EncodeToString(b)
}

func (s *Store) CreateAction(ctx context.Context, a model.ResponseAction) (model.ResponseAction, error) {
	a.ID = newActionID()
	a.Status = model.ActPending
	if RequiresApproval[a.Type] {
		a.Status = model.ActAwaitingApproval
	}
	a.CreatedAt = time.Now().UTC()
	a.UpdatedAt = a.CreatedAt
	params, _ := json.Marshal(a.Params)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO response_actions (id, agent_id, type, params, reason, status, result, created_by, approved_by, rollback_of, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, ?, ?)`,
		a.ID, a.AgentID, a.Type, string(params), a.Reason, a.Status, a.CreatedBy, a.RollbackOf, a.CreatedAt, a.UpdatedAt)
	return a, err
}

func (s *Store) GetAction(ctx context.Context, id string) (model.ResponseAction, error) {
	a, err := scanAction(s.db.QueryRowContext(ctx, `SELECT `+actionColumns+` FROM response_actions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *Store) ListActions(ctx context.Context, limit int) ([]model.ResponseAction, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+actionColumns+` FROM response_actions ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ResponseAction{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApproveAction 由另一位管理员批准，批准后进入待执行。
func (s *Store) ApproveAction(ctx context.Context, id, by string) error {
	a, err := s.GetAction(ctx, id)
	if err != nil {
		return err
	}
	if a.CreatedBy == by {
		return ErrSelfApproval
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE response_actions SET status = ?, approved_by = ?, updated_at = ? WHERE id = ? AND status = ? AND created_by <> ?`,
		model.ActPending, by, time.Now().UTC(), id, model.ActAwaitingApproval, by)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Rollback 为已执行的动作创建撤销动作（不需要审批，解除影响应尽快）。
func (s *Store) Rollback(ctx context.Context, id, by, reason string) (model.ResponseAction, error) {
	orig, err := s.GetAction(ctx, id)
	if err != nil {
		return orig, err
	}
	undo, ok := Rollbacks[orig.Type]
	if !ok || orig.Status != model.ActDone {
		return orig, ErrNotRollbackable
	}
	var existing int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM response_actions WHERE rollback_of = ? AND status NOT IN (?, ?)`,
		id, model.ActFailed, model.ActExpired).Scan(&existing); err != nil {
		return orig, err
	}
	if existing > 0 {
		return orig, ErrNotRollbackable
	}
	params := map[string]string{}
	switch undo {
	case model.ActUnblockIP:
		params["ip"] = orig.Params["ip"]
	case model.ActRestoreFile:
		params["quarantine_id"] = orig.ID
	}
	return s.CreateAction(ctx, model.ResponseAction{AgentID: orig.AgentID, Type: undo, Params: params,
		Reason: reason, CreatedBy: by, RollbackOf: orig.ID})
}

// ClaimActions 把待执行的处置转为指令。指令 5 分钟内有效，Agent 收到过期指令不执行。
func (s *Store) ClaimActions(ctx context.Context, agentID string) ([]model.AgentCommand, error) {
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(ctx, `
		UPDATE response_actions SET status = ?, updated_at = ? WHERE agent_id = ? AND status = ?
		RETURNING id, type, params`,
		model.ActSent, now, agentID, model.ActPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cmds []model.AgentCommand
	for rows.Next() {
		c := model.AgentCommand{Type: "action", ExpiresAt: now.Add(5 * time.Minute)}
		var params string
		if err := rows.Scan(&c.ID, &c.Action, &params); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(params), &c.Params)
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

func (s *Store) recordActionResult(ctx context.Context, agentID string, r model.CommandResult) error {
	status := model.ActDone
	if r.Status != "done" {
		status = model.ActFailed
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var rollbackOf string
	err = tx.QueryRowContext(ctx, `
		UPDATE response_actions SET status = ?, result = ?, updated_at = ? WHERE id = ? AND agent_id = ? AND status = ?
		RETURNING rollback_of`, status, r.Detail, now, r.ID, agentID, model.ActSent).Scan(&rollbackOf)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if status == model.ActDone && rollbackOf != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE response_actions SET status = ?, updated_at = ? WHERE id = ?`,
			model.ActRolledBack, now, rollbackOf); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ExpireActions：10 分钟未被 Agent 领取（离线？）或 24 小时未批准的处置作废。
func (s *Store) ExpireActions(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, c := range []struct {
		status model.ActionStatus
		age    time.Duration
		msg    string
	}{
		{model.ActPending, 10 * time.Minute, "Agent 10 分钟内未领取（离线？），已作废"},
		{model.ActAwaitingApproval, 24 * time.Hour, "24 小时内未获批准，已作废"},
		{model.ActSent, 10 * time.Minute, "Agent 已领取但 10 分钟内未回报结果"},
	} {
		res, err := s.db.ExecContext(ctx, `
			UPDATE response_actions SET status = ?, result = ?, updated_at = ? WHERE status = ? AND updated_at < ?`,
			model.ActExpired, c.msg, now.UTC(), c.status, now.Add(-c.age).UTC())
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}
