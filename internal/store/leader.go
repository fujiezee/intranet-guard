package store

import (
	"context"
	"database/sql"
	"log/slog"
	"sync/atomic"
	"time"
)

// leaderLockKey 是 PostgreSQL 咨询锁的第一个键（任意固定值，只需与其他应用不冲突）；第二个键取当前 schema 的哈希：
// 咨询锁在整个数据库范围内生效，同一数据库中不同 schema 的独立部署不应互相抢锁。
const leaderLockKey = 0x5afe_1ead

// Leader 在多个管理中心实例共用 PostgreSQL 时选出一个实例执行后台任务（推送、超时、离线检测、情报拉取、数据清理），
// 避免重复推送。实现为会话级咨询锁：持锁实例宕机或连接断开时锁自动释放，其他实例在一个检查周期内接手。
// SQLite 只支持单实例，总是主实例。
type Leader struct {
	s      *Store
	db     *sql.DB // 选主专用的连接池：不能与请求处理共用，否则高负载时连接池被占满，主实例宕机后无人能接手
	leader atomic.Bool
	conn   *sql.Conn
	// Interval 是获取锁 / 检查连接的周期
	Interval time.Duration
}

func (s *Store) NewLeader() *Leader {
	l := &Leader{s: s, Interval: 5 * time.Second}
	if s.db.d != dialectPostgres {
		l.leader.Store(true)
		return l
	}
	db, err := sql.Open("pgx", s.dsn)
	if err != nil { // 只解析 DSN，不会在这里失败（Open 时已用同一 DSN 成功连接过）
		slog.Error("leader election pool", "err", err)
		return l
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	l.db = db
	return l
}

func (l *Leader) IsLeader() bool { return l.leader.Load() }

// Run 持续竞选，直到 ctx 结束（结束时释放锁）。
func (l *Leader) Run(ctx context.Context) {
	if l.db == nil {
		return
	}
	defer l.db.Close()
	t := time.NewTicker(l.Interval)
	defer t.Stop()
	defer l.release()
	for {
		l.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (l *Leader) check(ctx context.Context) {
	if l.conn != nil {
		// 已是主实例：确认持锁的连接仍然有效
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := l.conn.PingContext(cctx)
		cancel()
		if err == nil {
			return
		}
		slog.Warn("lost leadership: database connection broken", "err", err)
		l.release()
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := l.db.Conn(cctx)
	if err != nil {
		return
	}
	var ok bool
	if err := conn.QueryRowContext(cctx, `SELECT pg_try_advisory_lock($1, hashtext(current_schema()))`, leaderLockKey).Scan(&ok); err != nil || !ok {
		conn.Close()
		return
	}
	l.conn = conn
	l.leader.Store(true)
	slog.Info("became leader: running background jobs on this instance")
}

func (l *Leader) release() {
	l.leader.Store(false)
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, hashtext(current_schema()))`, leaderLockKey)
		cancel()
		_ = l.conn.Close()
		l.conn = nil
	}
}
