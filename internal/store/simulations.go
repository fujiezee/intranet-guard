package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"safe/internal/model"
	"safe/internal/simulate"
)

// CreateSimulation 登记一次待执行的自检，Agent 下次上报时领取。
func (s *Store) CreateSimulation(ctx context.Context, agentID, scenario string, params map[string]string, by string) (model.Simulation, error) {
	sc, _ := simulate.Get(scenario)
	p, _ := json.Marshal(params)
	sim := model.Simulation{ID: simulate.NewID(), AgentID: agentID, Scenario: scenario, Status: model.SimPending,
		CreatedBy: by, CreatedAt: time.Now().UTC()}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO simulations (id, agent_id, scenario, params, status, timeout_sec, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sim.ID, agentID, scenario, string(p), sim.Status, int(sc.Timeout.Seconds()), by, sim.CreatedAt)
	return sim, err
}

// ClaimSimulations 把 Agent 待执行的自检标记为执行中并转成指令。
func (s *Store) ClaimSimulations(ctx context.Context, agentID string) ([]model.AgentCommand, error) {
	rows, err := s.db.QueryContext(ctx, `
		UPDATE simulations SET status = ?, started_at = ? WHERE agent_id = ? AND status = ?
		RETURNING id, scenario, params`,
		model.SimRunning, time.Now().UTC(), agentID, model.SimPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cmds := []model.AgentCommand{}
	for rows.Next() {
		c := model.AgentCommand{Type: "simulate"}
		var params string
		if err := rows.Scan(&c.ID, &c.Scenario, &params); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(params), &c.Params)
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

// RecordCommandResults 记录 Agent 报告的执行结果。执行成功（done）时不改状态，等待告警出现；
// 不适用或出错时直接结束该自检。
func (s *Store) RecordCommandResults(ctx context.Context, agentID string, results []model.CommandResult) error {
	for _, r := range results {
		var status model.SimulationStatus
		switch r.Status {
		case "not_applicable":
			status = model.SimNotApplicable
		case "error":
			status = model.SimError
		default:
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE simulations SET status = ?, detail = ?, finished_at = ? WHERE id = ? AND agent_id = ? AND status = ?`,
			status, r.Detail, time.Now().UTC(), r.ID, agentID, model.SimRunning); err != nil {
			return err
		}
	}
	return nil
}

// ExpireSimulations 把超过时限仍未检测到的自检标记为失败（即检测能力有问题），返回数量。
func (s *Store) ExpireSimulations(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, timeout_sec FROM simulations WHERE status = ?`, model.SimRunning)
	if err != nil {
		return 0, err
	}
	var expired []string
	for rows.Next() {
		var id string
		var started sql.NullTime
		var timeout int
		if err := rows.Scan(&id, &started, &timeout); err != nil {
			rows.Close()
			return 0, err
		}
		if started.Valid && now.Sub(started.Time) > time.Duration(timeout)*time.Second {
			expired = append(expired, id)
		}
	}
	rows.Close()
	for _, id := range expired {
		if _, err := s.db.ExecContext(ctx, `
			UPDATE simulations SET status = ?, detail = ?, finished_at = ? WHERE id = ? AND status = ?`,
			model.SimFailed, "超时未检测到", now.UTC(), id, model.SimRunning); err != nil {
			return 0, err
		}
	}
	// Agent 离线时待执行的自检不会被领取，超过 10 分钟同样判为失败。
	res, err := s.db.ExecContext(ctx, `
		UPDATE simulations SET status = ?, detail = ?, finished_at = ? WHERE status = ? AND created_at < ?`,
		model.SimFailed, "Agent 未领取（离线？）", now.UTC(), model.SimPending, now.Add(-10*time.Minute).UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return len(expired) + int(n), nil
}

func (s *Store) ListSimulations(ctx context.Context, limit int) ([]model.Simulation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, agent_id, scenario, status, detail, alert_id, latency_ms, created_by, created_at, started_at, finished_at
		FROM simulations ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Simulation{}
	for rows.Next() {
		var m model.Simulation
		var started, finished sql.NullTime
		if err := rows.Scan(&m.ID, &m.AgentID, &m.Scenario, &m.Status, &m.Detail, &m.AlertID, &m.LatencyMs,
			&m.CreatedBy, &m.CreatedAt, &started, &finished); err != nil {
			return nil, err
		}
		if started.Valid {
			m.StartedAt = &started.Time
		}
		if finished.Valid {
			m.FinishedAt = &finished.Time
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
