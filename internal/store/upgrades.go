package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"safe/internal/version"
)

// UpgradePolicy 是 Agent 升级策略。
type UpgradePolicy struct {
	Mode          string `json:"mode"`           // manual：只升级管理员选择的主机；auto：自动升级所有旧版本
	MaxConcurrent int    `json:"max_concurrent"` // 同时升级的主机数上限（分批）
	MaxFailures   int    `json:"max_failures"`   // 同一版本失败达到该数量时暂停自动升级
	Paused        bool   `json:"paused"`
	PausedReason  string `json:"paused_reason,omitempty"`
}

func DefaultUpgradePolicy() UpgradePolicy {
	return UpgradePolicy{Mode: "manual", MaxConcurrent: 20, MaxFailures: 3}
}

// 升级状态
const (
	UpgradeQueued    = "queued"    // 管理员已选择，等待 Agent 下次上报时下发
	UpgradeRunning   = "upgrading" // 已下发，等待 Agent 以新版本重新上报
	UpgradeSucceeded = "succeeded"
	UpgradeFailed    = "failed"
)

// UpgradeTimeout：下发后这么久没有以新版本上报即判为失败（离线、卡住或回退）。
const UpgradeTimeout = 10 * time.Minute

type AgentUpgrade struct {
	AgentID     string    `json:"agent_id"`
	Attempt     string    `json:"attempt,omitempty"`
	Target      string    `json:"target"`
	State       string    `json:"state"`
	Detail      string    `json:"detail,omitempty"`
	RequestedBy string    `json:"requested_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const upgradePolicyKey = "upgrade_policy"

func (s *Store) UpgradePolicy(ctx context.Context) (UpgradePolicy, error) {
	p := DefaultUpgradePolicy()
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, upgradePolicyKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	} else if err != nil {
		return p, err
	}
	return p, json.Unmarshal([]byte(raw), &p)
}

func (s *Store) SetUpgradePolicy(ctx context.Context, p UpgradePolicy) error {
	raw, _ := json.Marshal(p)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		upgradePolicyKey, string(raw))
	return err
}

func (s *Store) ListUpgrades(ctx context.Context) (map[string]AgentUpgrade, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT agent_id, attempt, target, state, detail, requested_by, updated_at FROM agent_upgrades`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AgentUpgrade{}
	for rows.Next() {
		var u AgentUpgrade
		if err := rows.Scan(&u.AgentID, &u.Attempt, &u.Target, &u.State, &u.Detail, &u.RequestedBy, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out[u.AgentID] = u
	}
	return out, rows.Err()
}

// QueueUpgrades 把选中的 Agent 排入升级（正在升级的跳过），返回排入的数量。
func (s *Store) QueueUpgrades(ctx context.Context, agentIDs []string, target, by string) (int, error) {
	n := 0
	now := time.Now().UTC()
	for _, id := range agentIDs {
		res, err := s.db.ExecContext(ctx, `
			INSERT INTO agent_upgrades (agent_id, attempt, target, state, detail, requested_by, updated_at)
			VALUES (?, '', ?, ?, '', ?, ?)
			ON CONFLICT(agent_id) DO UPDATE SET attempt = '', target = excluded.target, state = excluded.state, detail = '',
				requested_by = excluded.requested_by, updated_at = excluded.updated_at
			WHERE agent_upgrades.state <> ?`,
			id, target, UpgradeQueued, by, now, UpgradeRunning)
		if err != nil {
			return n, err
		}
		if k, _ := res.RowsAffected(); k > 0 {
			n++
		}
	}
	return n, nil
}

func newAttempt() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "upg-" + hex.EncodeToString(b)
}

// NextUpgrade 在 Agent 上报时调用：先根据上报的版本确认正在进行的升级是否已完成，
// 再判断是否要向它下发升级（已排队，或自动模式下版本落后且未超出并发与失败上限）。
// 返回需要下发的升级编号和目标版本；不需要时 attempt 为空。
func (s *Store) NextUpgrade(ctx context.Context, agentID, current, latest string, p UpgradePolicy) (attempt, target string, err error) {
	now := time.Now().UTC()
	var u AgentUpgrade
	err = s.db.QueryRowContext(ctx, `SELECT attempt, target, state FROM agent_upgrades WHERE agent_id = ?`, agentID).
		Scan(&u.Attempt, &u.Target, &u.State)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if exists && u.State == UpgradeRunning {
		if current == u.Target {
			_, err = s.db.ExecContext(ctx, `
				UPDATE agent_upgrades SET state = ?, detail = '', updated_at = ? WHERE agent_id = ? AND state = ?`,
				UpgradeSucceeded, now, agentID, UpgradeRunning)
		}
		return "", "", err // 进行中或刚完成，本次不再下发
	}
	if latest == "" {
		return "", "", nil
	}
	if current == latest {
		if exists && u.State == UpgradeQueued {
			_, err = s.db.ExecContext(ctx, `
				UPDATE agent_upgrades SET state = ?, detail = '已是最新版本', updated_at = ? WHERE agent_id = ? AND state = ?`,
				UpgradeSucceeded, now, agentID, UpgradeQueued)
		}
		return "", "", err
	}
	switch {
	case exists && u.State == UpgradeQueued:
		// 手动选择的升级：总是升级到管理中心当前提供的版本
	case p.Mode == "auto" && !p.Paused && version.Older(current, latest):
		if exists && u.Target == latest && u.State == UpgradeFailed {
			return "", "", nil // 这个版本在这台主机上已经失败过，不自动重试（可手动重试）
		}
		var running int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_upgrades WHERE state = ?`, UpgradeRunning).Scan(&running); err != nil {
			return "", "", err
		}
		if running >= p.MaxConcurrent {
			return "", "", nil // 本批已满，等下一批
		}
	default:
		return "", "", nil
	}
	attempt = newAttempt()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO agent_upgrades (agent_id, attempt, target, state, detail, requested_by, updated_at)
		VALUES (?, ?, ?, ?, '', '自动升级', ?)
		ON CONFLICT(agent_id) DO UPDATE SET attempt = excluded.attempt, target = excluded.target, state = excluded.state,
			detail = '', updated_at = excluded.updated_at`,
		agentID, attempt, latest, UpgradeRunning, now)
	return attempt, latest, err
}

// FailUpgrade 记录升级失败；自动模式下同一版本的失败达到上限时暂停自动升级。
func (s *Store) FailUpgrade(ctx context.Context, agentID, attempt, detail string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE agent_upgrades SET state = ?, detail = ?, updated_at = ? WHERE agent_id = ? AND attempt = ? AND state = ?`,
		UpgradeFailed, detail, time.Now().UTC(), agentID, attempt, UpgradeRunning)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	return s.checkPause(ctx)
}

func (s *Store) checkPause(ctx context.Context) error {
	p, err := s.UpgradePolicy(ctx)
	if err != nil || p.Mode != "auto" || p.Paused {
		return err
	}
	var target string
	var failed int
	err = s.db.QueryRowContext(ctx, `
		SELECT target, COUNT(*) FROM agent_upgrades WHERE state = ? GROUP BY target ORDER BY COUNT(*) DESC LIMIT 1`,
		UpgradeFailed).Scan(&target, &failed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if failed >= p.MaxFailures {
		p.Paused = true
		p.PausedReason = fmt.Sprintf("版本 %s 已有 %d 台主机升级失败，自动升级已暂停；排查原因后在控制台恢复", target, failed)
		return s.SetUpgradePolicy(ctx, p)
	}
	return nil
}

// ExpireUpgrades 把下发后超时未以新版本上报的升级判为失败，返回数量。
func (s *Store) ExpireUpgrades(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE agent_upgrades SET state = ?, detail = ?, updated_at = ? WHERE state = ? AND updated_at < ?`,
		UpgradeFailed, "超时：升级后 10 分钟内没有以新版本重新上线（离线，或新版本无法运行）", now.UTC(), UpgradeRunning, now.Add(-UpgradeTimeout).UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return n, s.checkPause(ctx)
	}
	return n, nil
}
