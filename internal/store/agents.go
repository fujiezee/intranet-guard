package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
)

// MaxEventsPerReport 限制单次上报的事件数量。
const MaxEventsPerReport = 50000

var ErrTooManyEvents = errors.New("too many events in one report")

// SaveAgentReport 记录 Agent 心跳和事件，并执行主机检测规则。
// 事件先写入事件存储（可能是独立的 ClickHouse），再在主库事务中更新 Agent 状态、生成告警；
// 后一步失败时 Agent 会重报，事件可能重复一份，告警由去重键保证不重复。
func (s *Store) SaveAgentReport(ctx context.Context, rep model.AgentReport) error {
	if len(rep.Events) > MaxEventsPerReport {
		return ErrTooManyEvents
	}
	if err := s.events.InsertHostEvents(ctx, rep.Agent.ID, rep.Events); err != nil {
		return err
	}
	a := rep.Agent
	// 检测要查询事件存储，必须在开启主库事务之前完成：SQLite 只有一个连接，事务内再查会死锁。
	hostIP, err := primaryIP(ctx, s.db, a)
	if err != nil {
		return err
	}
	alerts, err := s.detectHostAlerts(ctx, hostIP, a.ID, rep.Events)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	ips, _ := json.Marshal(a.IPs)
	status := model.AgentOnline
	if a.Stopping {
		status = model.AgentStopped // 不再参与离线检测，避免关机后再报一次"离线"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, version, ips, capabilities, status, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET hostname = excluded.hostname, os = excluded.os, version = excluded.version,
			ips = excluded.ips, capabilities = excluded.capabilities, status = excluded.status, last_seen = excluded.last_seen`,
		a.ID, a.Hostname, a.OS, a.Version, string(ips), strings.Join(a.Capabilities, ","), status, now.UnixMilli()); err != nil {
		return err
	}
	if a.Stopping {
		alerts = append(alerts, alert.AgentStopped(hostIP, a.ID))
	}

	for _, al := range alerts {
		if err := insertDedupAlert(ctx, tx, al, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// primaryIP 选出用于告警关联的主机 IP：优先选已在资产库中的地址。
func primaryIP(ctx context.Context, q querier, a model.AgentInfo) (string, error) {
	for _, ip := range a.IPs {
		var one int
		err := q.QueryRowContext(ctx, `SELECT 1 FROM assets WHERE ip = ?`, ip).Scan(&one)
		if err == nil {
			return ip, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	if len(a.IPs) > 0 {
		return a.IPs[0], nil
	}
	return a.Hostname, nil
}

func (s *Store) detectHostAlerts(ctx context.Context, hostIP, agentID string, events []model.HostEvent) ([]alert.DedupAlert, error) {
	countFailures := func(srcIP string, from, to time.Time) (int, error) {
		return s.events.CountLoginFailures(ctx, agentID, srcIP, from, to)
	}

	var alerts []alert.DedupAlert
	latestFailure := map[string]time.Time{} // 每个来源在本批中最后一次失败的时间
	for _, ev := range events {
		switch ev.Type {
		case model.EventLoginFailed:
			if ev.SrcIP != "" && ev.Time.After(latestFailure[ev.SrcIP]) {
				latestFailure[ev.SrcIP] = ev.Time
			}
		case model.EventLoginSuccess:
			if ev.User == "root" {
				alerts = append(alerts, alert.RootLogin(hostIP, agentID, ev))
			}
			if ev.SrcIP != "" {
				n, err := countFailures(ev.SrcIP, ev.Time.Add(-alert.BruteForceLookback), ev.Time)
				if err != nil {
					return nil, err
				}
				if n >= alert.BruteForceThreshold {
					alerts = append(alerts, alert.BruteForceSuccess(hostIP, agentID, ev))
				}
				if a, err := netip.ParseAddr(ev.SrcIP); err == nil && (a.IsPrivate() || a.IsLoopback()) {
					// 内网来源：短时间登录多台主机即横向移动（跳板机等合法场景可标记误报）
					targets, err := s.events.CountLoginTargets(ctx, ev.SrcIP, ev.Time.Add(-alert.LateralWindow), ev.Time)
					if err != nil {
						return nil, err
					}
					if targets >= alert.LateralTargets {
						alerts = append(alerts, alert.LateralMovement(ev.SrcIP, ev.User, targets))
					}
				}
			}
		case model.EventFileChanged:
			alerts = append(alerts, alert.FileChanged(hostIP, agentID, ev))
		case model.EventSuspiciousProcess:
			alerts = append(alerts, alert.SuspiciousProcess(hostIP, agentID, ev))
		case model.EventSuspiciousCommand:
			alerts = append(alerts, alert.SuspiciousCommand(hostIP, agentID, ev))
		case model.EventWebshell:
			alerts = append(alerts, alert.Webshell(hostIP, agentID, ev))
		case model.EventAccountChange:
			alerts = append(alerts, alert.AccountChange(hostIP, agentID, ev))
		case model.EventDomainAttack:
			alerts = append(alerts, alert.DomainAttack(hostIP, agentID, ev))
		}
	}
	for src, last := range latestFailure {
		n, err := countFailures(src, last.Add(-alert.BruteForceWindow), last)
		if err != nil {
			return nil, err
		}
		if n >= alert.BruteForceThreshold {
			alerts = append(alerts, alert.SSHBruteForce(hostIP, agentID, src, n))
		}
	}
	return alerts, nil
}

func insertDedupAlert(ctx context.Context, tx *Tx, a alert.DedupAlert, at time.Time) error {
	if a.DedupKey != "" {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM alerts WHERE dedup_key = ? AND created_at >= ? LIMIT 1`,
			a.DedupKey, at.Add(-alert.DedupWindow)).Scan(&one)
		if err == nil {
			return nil // 窗口内已告警过
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return insertAlertRow(ctx, tx, a.Alert, a.DedupKey, at)
}

// MarkOfflineAgents 把超过 cutoff 没有心跳的在线 Agent 标记为离线并告警，返回本次离线的数量。
// 单条 UPDATE … RETURNING 保证多个管理中心实例同时检测时每次离线只告警一次。
func (s *Store) MarkOfflineAgents(ctx context.Context, cutoff time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		UPDATE agents SET status = ? WHERE status = ? AND last_seen < ? RETURNING id, hostname, ips, last_seen`,
		model.AgentOffline, model.AgentOnline, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	var offline []model.AgentInfo
	for rows.Next() {
		var a model.AgentInfo
		var ips string
		var lastSeen int64
		if err := rows.Scan(&a.ID, &a.Hostname, &ips, &lastSeen); err != nil {
			rows.Close()
			return 0, err
		}
		_ = json.Unmarshal([]byte(ips), &a.IPs)
		a.LastSeen = time.UnixMilli(lastSeen)
		offline = append(offline, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	for _, a := range offline {
		ip, err := primaryIP(ctx, tx, a)
		if err != nil {
			return 0, err
		}
		if err := insertDedupAlert(ctx, tx, alert.AgentOffline(ip, a.ID, a.LastSeen), now); err != nil {
			return 0, err
		}
	}
	return len(offline), tx.Commit()
}

func (s *Store) ListAgents(ctx context.Context) ([]model.AgentInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, hostname, os, version, ips, capabilities, status, last_seen FROM agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := []model.AgentInfo{}
	for rows.Next() {
		var a model.AgentInfo
		var ips, caps string
		var lastSeen int64
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.Version, &ips, &caps, &a.Status, &lastSeen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ips), &a.IPs)
		if caps != "" {
			a.Capabilities = strings.Split(caps, ",")
		}
		a.LastSeen = time.UnixMilli(lastSeen).UTC()
		agents = append(agents, a)
	}
	return agents, rows.Err()
}
