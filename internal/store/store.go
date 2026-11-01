// Package store 是管理中心的持久化层：开发和小规模部署用 SQLite，生产环境用 PostgreSQL。
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/vuln"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db       *DB
	dsn      string // 选主需要单独建立连接
	events   EventStore
	intel    intelCache    // 管理中心侧情报匹配用的缓存，按情报版本刷新
	logins   loginWindow   // 横向移动检测
	failures failureWindow // 暴力破解检测
}

const schema = `
CREATE TABLE IF NOT EXISTS assets (
	ip         TEXT PRIMARY KEY,
	hostname   TEXT NOT NULL DEFAULT '',
	probe_id   TEXT NOT NULL,
	importance TEXT NOT NULL DEFAULT 'normal',
	owner      TEXT NOT NULL DEFAULT '',
	tags       TEXT NOT NULL DEFAULT '',
	first_seen TIMESTAMP NOT NULL,
	last_seen  TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
	ip        TEXT NOT NULL REFERENCES assets(ip) ON DELETE CASCADE,
	port      INTEGER NOT NULL,
	proto     TEXT NOT NULL,
	service   TEXT NOT NULL DEFAULT '',
	banner    TEXT NOT NULL DEFAULT '',
	last_seen TIMESTAMP NOT NULL,
	PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS tasks (
	id         TEXT PRIMARY KEY,
	probe_id   TEXT NOT NULL,
	targets    TEXT NOT NULL,
	ports      TEXT NOT NULL,
	baseline   BOOLEAN NOT NULL DEFAULT FALSE,
	kind       TEXT NOT NULL DEFAULT 'discovery',
	weak_password BOOLEAN NOT NULL DEFAULT FALSE,
	status     TEXT NOT NULL,
	error      TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS tasks_probe_status ON tasks(probe_id, status);
CREATE TABLE IF NOT EXISTS alerts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	type       TEXT NOT NULL,
	severity   TEXT NOT NULL,
	ip         TEXT NOT NULL,
	port       INTEGER NOT NULL DEFAULT 0,
	message    TEXT NOT NULL,
	status     TEXT NOT NULL,
	acked_by   TEXT NOT NULL DEFAULT '',
	dedup_key  TEXT NOT NULL DEFAULT '',
	resolution      TEXT NOT NULL DEFAULT '',
	resolution_note TEXT NOT NULL DEFAULT '',
	incident_id     INTEGER NOT NULL DEFAULT 0,
	notified        BOOLEAN NOT NULL DEFAULT TRUE, -- 新告警写入时为 FALSE，推送后置为 TRUE
	notify_claimed_at TIMESTAMP,                   -- 推送领取时间（租约），见 ClaimPendingAlerts
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS alerts_dedup ON alerts(dedup_key, created_at);
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL,
	created_at    TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
	id        TEXT PRIMARY KEY,
	hostname  TEXT NOT NULL,
	os        TEXT NOT NULL,
	version   TEXT NOT NULL,
	ips       TEXT NOT NULL,
	capabilities TEXT NOT NULL DEFAULT '',
	status    TEXT NOT NULL,
	last_seen INTEGER NOT NULL -- unix 毫秒
);
CREATE TABLE IF NOT EXISTS host_events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	agent_id TEXT NOT NULL,
	type     TEXT NOT NULL,
	ts       INTEGER NOT NULL, -- unix 毫秒
	"user"   TEXT NOT NULL DEFAULT '',
	src_ip   TEXT NOT NULL DEFAULT '',
	path     TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS host_events_ts ON host_events(ts);
CREATE INDEX IF NOT EXISTS host_events_login ON host_events(agent_id, type, src_ip, ts);
CREATE TABLE IF NOT EXISTS ids_events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	probe_id     TEXT NOT NULL,
	ts           INTEGER NOT NULL, -- unix 毫秒
	src_ip       TEXT NOT NULL,
	src_port     INTEGER NOT NULL,
	dest_ip      TEXT NOT NULL,
	dest_port    INTEGER NOT NULL,
	proto        TEXT NOT NULL,
	app_proto    TEXT NOT NULL,
	signature_id INTEGER NOT NULL,
	signature    TEXT NOT NULL,
	category     TEXT NOT NULL,
	severity     INTEGER NOT NULL,
	action       TEXT NOT NULL,
	suppressed   BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS ids_events_ts ON ids_events(ts);
CREATE TABLE IF NOT EXISTS ids_suppressions (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	signature_id INTEGER NOT NULL,
	src_ip       TEXT NOT NULL DEFAULT '', -- 空表示所有来源
	note         TEXT NOT NULL DEFAULT '',
	created_by   TEXT NOT NULL,
	created_at   TIMESTAMP NOT NULL,
	UNIQUE (signature_id, src_ip)
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash TEXT NOT NULL UNIQUE,
	kind       TEXT NOT NULL,
	max_uses   INTEGER NOT NULL,
	uses       INTEGER NOT NULL,
	expires_at INTEGER NOT NULL, -- unix 秒
	note       TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
	kind        TEXT NOT NULL,
	id          TEXT NOT NULL,
	serial      TEXT NOT NULL,
	status      TEXT NOT NULL,
	cert_expiry INTEGER NOT NULL, -- unix 秒
	enrolled_at TIMESTAMP NOT NULL,
	token_id    INTEGER NOT NULL,
	PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS vulns (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ip         TEXT NOT NULL,
	port       INTEGER NOT NULL,
	check_id   TEXT NOT NULL,
	title      TEXT NOT NULL,
	severity   TEXT NOT NULL,
	detail     TEXT NOT NULL,
	status     TEXT NOT NULL,
	first_seen TIMESTAMP NOT NULL,
	last_seen  TIMESTAMP NOT NULL,
	fixed_at   TIMESTAMP,
	UNIQUE (ip, port, check_id)
);
CREATE INDEX IF NOT EXISTS vulns_status ON vulns(status, severity);
CREATE TABLE IF NOT EXISTS notify_channels (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	type         TEXT NOT NULL,
	url          TEXT NOT NULL,
	secret       TEXT NOT NULL DEFAULT '',
	min_severity TEXT NOT NULL,
	enabled      BOOLEAN NOT NULL,
	last_error   TEXT NOT NULL DEFAULT '',
	last_sent_at TIMESTAMP,
	created_at   TIMESTAMP NOT NULL
);
-- 告警推送进度：只有一行，多实例部署时通过比较并交换保证每条告警只推送一次
CREATE TABLE IF NOT EXISTS notify_cursor (
	id      INTEGER PRIMARY KEY,
	last_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        TIMESTAMP NOT NULL,
	username  TEXT NOT NULL,
	action    TEXT NOT NULL,
	target    TEXT NOT NULL DEFAULT '',
	detail    TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL,
	success   BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS honeypots (
	probe_id       TEXT PRIMARY KEY,
	enabled        BOOLEAN NOT NULL,
	services       TEXT NOT NULL,
	ignore_sources TEXT NOT NULL,
	probe_ips      TEXT NOT NULL DEFAULT '[]', -- 探针上报的本机地址，用于在资产中标识蜜罐
	status         TEXT NOT NULL DEFAULT '{}', -- 各端口监听状态
	seen_at        TIMESTAMP,
	updated_at     TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS honeypot_events (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	probe_id      TEXT NOT NULL,
	ts            TIMESTAMP NOT NULL,
	service       TEXT NOT NULL,
	port          INTEGER NOT NULL,
	src_ip        TEXT NOT NULL,
	src_port      INTEGER NOT NULL,
	username      TEXT NOT NULL DEFAULT '',
	password      TEXT NOT NULL DEFAULT '',
	detail        TEXT NOT NULL DEFAULT '',
	simulation_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS honeypot_events_ts ON honeypot_events(ts);
CREATE TABLE IF NOT EXISTS simulations (
	id          TEXT PRIMARY KEY,
	agent_id    TEXT NOT NULL,
	scenario    TEXT NOT NULL,
	params      TEXT NOT NULL DEFAULT '{}',
	status      TEXT NOT NULL,
	detail      TEXT NOT NULL DEFAULT '',
	alert_id    INTEGER NOT NULL DEFAULT 0,
	latency_ms  INTEGER NOT NULL DEFAULT 0,
	timeout_sec INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	created_at  TIMESTAMP NOT NULL,
	started_at  TIMESTAMP,
	finished_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS simulations_agent ON simulations(agent_id, status);
CREATE TABLE IF NOT EXISTS response_actions (
	id          TEXT PRIMARY KEY,
	agent_id    TEXT NOT NULL,
	type        TEXT NOT NULL,
	params      TEXT NOT NULL,
	reason      TEXT NOT NULL,
	status      TEXT NOT NULL,
	result      TEXT NOT NULL DEFAULT '',
	created_by  TEXT NOT NULL,
	approved_by TEXT NOT NULL DEFAULT '',
	rollback_of TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMP NOT NULL,
	updated_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS response_actions_agent ON response_actions(agent_id, status);
CREATE TABLE IF NOT EXISTS incidents (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ip          TEXT NOT NULL,
	title       TEXT NOT NULL,
	severity    TEXT NOT NULL,
	status      TEXT NOT NULL,
	assignee    TEXT NOT NULL DEFAULT '',
	stages      TEXT NOT NULL DEFAULT '',
	alert_count INTEGER NOT NULL,
	first_seen  TIMESTAMP NOT NULL,
	last_seen   TIMESTAMP NOT NULL,
	created_at  TIMESTAMP NOT NULL,
	updated_at  TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_ip ON incidents(ip, status, last_seen);
CREATE TABLE IF NOT EXISTS incident_notes (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id INTEGER NOT NULL,
	author      TEXT NOT NULL,
	body        TEXT NOT NULL,
	created_at  TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_indicators (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	type       TEXT NOT NULL,
	value      TEXT NOT NULL,
	source     TEXT NOT NULL,
	severity   TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL,
	UNIQUE (source, type, value)
);
CREATE INDEX IF NOT EXISTS intel_indicators_value ON intel_indicators(value);
CREATE TABLE IF NOT EXISTS intel_feeds (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	url        TEXT NOT NULL,
	severity   TEXT NOT NULL,
	enabled    BOOLEAN NOT NULL,
	count      INTEGER NOT NULL DEFAULT 0,
	last_fetch TIMESTAMP,
	last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS intel_meta (
	id         INTEGER PRIMARY KEY,
	version    INTEGER NOT NULL,
	net_config TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS asset_groups (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	kind       TEXT NOT NULL,
	members    TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_upgrades (
	agent_id     TEXT PRIMARY KEY,
	attempt      TEXT NOT NULL,
	target       TEXT NOT NULL,
	state        TEXT NOT NULL,
	detail       TEXT NOT NULL,
	requested_by TEXT NOT NULL,
	updated_at   TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash   TEXT NOT NULL UNIQUE,
	name         TEXT NOT NULL,
	created_by   TEXT NOT NULL,
	created_at   TIMESTAMP NOT NULL,
	last_used_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL -- unix 秒
);
`

// Open 打开数据库并建表。dsn 以 postgres:// 或 postgresql:// 开头时使用 PostgreSQL，否则视为 SQLite 文件路径。
func Open(dsn string) (*Store, error) {
	st, err := open(dsn)
	if err == nil {
		st.dsn = dsn
	}
	return st, err
}

func open(dsn string) (*Store, error) {
	var db *DB
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sqlDB, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		sqlDB.SetMaxOpenConns(20)
		// 空闲连接数默认只有 2：并发上报时其余连接用完即关、下次重建，压测中耗尽本机端口（TIME_WAIT）
		sqlDB.SetMaxIdleConns(20)
		sqlDB.SetConnMaxIdleTime(5 * time.Minute)
		db = &DB{DB: sqlDB, d: dialectPostgres}
	} else {
		sqlDB, err := sql.Open("sqlite", dsn+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
		if err != nil {
			return nil, err
		}
		sqlDB.SetMaxOpenConns(1) // SQLite 单写者
		db = &DB{DB: sqlDB, d: dialectSQLite}
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, events: &sqlEvents{db: db}}, nil
}

// addedColumns 是建表之后新增的列。新库由建表语句直接包含；旧库在启动时补齐。
var addedColumns = []struct{ table, column, def string }{
	{"alerts", "dedup_key", "TEXT NOT NULL DEFAULT ''"},
	{"tasks", "kind", "TEXT NOT NULL DEFAULT 'discovery'"},
	{"tasks", "weak_password", "BOOLEAN NOT NULL DEFAULT FALSE"},
	{"alerts", "resolution", "TEXT NOT NULL DEFAULT ''"},
	{"alerts", "resolution_note", "TEXT NOT NULL DEFAULT ''"},
	{"agents", "capabilities", "TEXT NOT NULL DEFAULT ''"},
	{"alerts", "incident_id", "INTEGER NOT NULL DEFAULT 0"},
	// 升级时已有告警视为已推送，避免升级后把历史告警重新推送一遍
	{"alerts", "notified", "BOOLEAN NOT NULL DEFAULT TRUE"},
	{"alerts", "notify_claimed_at", "TIMESTAMP"},
	{"assets", "importance", "TEXT NOT NULL DEFAULT 'normal'"},
	{"assets", "owner", "TEXT NOT NULL DEFAULT ''"},
	{"assets", "tags", "TEXT NOT NULL DEFAULT ''"},
}

func initSchema(db *DB) error {
	if db.d == dialectSQLite {
		// SQLite 不支持 ADD COLUMN IF NOT EXISTS；且必须在建索引之前补列。
		for _, c := range addedColumns {
			if _, err := db.Exec(`ALTER TABLE ` + c.table + ` ADD COLUMN ` + c.column + ` ` + c.def); err != nil &&
				!strings.Contains(err.Error(), "duplicate column") && !strings.Contains(err.Error(), "no such table") {
				return err
			}
		}
	}
	if _, err := db.Exec(schemaFor(db.d)); err != nil {
		return err
	}
	if db.d == dialectPostgres {
		for _, c := range addedColumns {
			if _, err := db.Exec(`ALTER TABLE ` + c.table + ` ADD COLUMN IF NOT EXISTS ` + c.column + ` ` + c.def); err != nil {
				return err
			}
		}
	}
	// 依赖补加列的索引，必须在补列之后创建
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS alerts_unnotified ON alerts(id) WHERE NOT notified`)
	return err
}

// Close 先写完事件存储中尚在批处理的事件（ClickHouse），再关闭主库。
func (s *Store) Close() error {
	if c, ok := s.events.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	return s.db.Close()
}

func (s *Store) CreateTask(ctx context.Context, t model.ScanTask) error {
	targets, _ := json.Marshal(t.Targets)
	ports, _ := json.Marshal(t.Ports)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tasks (id, probe_id, targets, ports, baseline, kind, weak_password, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ProbeID, string(targets), string(ports), t.Baseline, t.Kind, t.WeakPassword, t.Status, t.CreatedAt, t.UpdatedAt)
	return err
}

const taskColumns = `id, probe_id, targets, ports, baseline, kind, weak_password, status, error, created_at, updated_at`

func scanTask(row interface{ Scan(...any) error }) (model.ScanTask, error) {
	var t model.ScanTask
	var targets, ports string
	if err := row.Scan(&t.ID, &t.ProbeID, &targets, &ports, &t.Baseline, &t.Kind, &t.WeakPassword,
		&t.Status, &t.Error, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return t, err
	}
	_ = json.Unmarshal([]byte(targets), &t.Targets)
	_ = json.Unmarshal([]byte(ports), &t.Ports)
	return t, nil
}

func (s *Store) GetTask(ctx context.Context, id string) (model.ScanTask, error) {
	t, err := scanTask(s.db.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (s *Store) ListTasks(ctx context.Context) ([]model.ScanTask, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+taskColumns+` FROM tasks ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []model.ScanTask{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// ClaimTasks 把指定探针的 pending 任务标记为 running 并返回。单条 UPDATE … RETURNING 保证
// 多个管理中心实例并发时同一任务也只会被领取一次。
func (s *Store) ClaimTasks(ctx context.Context, probeID string) ([]model.ScanTask, error) {
	rows, err := s.db.QueryContext(ctx,
		`UPDATE tasks SET status = ?, updated_at = ? WHERE probe_id = ? AND status = ? RETURNING `+taskColumns,
		model.TaskRunning, time.Now().UTC(), probeID, model.TaskPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []model.ScanTask{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.Before(tasks[j].CreatedAt) })
	return tasks, rows.Err()
}

// SaveReport 合并扫描结果到资产库，并结束对应任务。
func (s *Store) SaveReport(ctx context.Context, r model.ScanReport) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var portsJSON string
	var baseline bool
	err = tx.QueryRowContext(ctx, `SELECT ports, baseline FROM tasks WHERE id = ? AND probe_id = ?`, r.TaskID, r.ProbeID).
		Scan(&portsJSON, &baseline)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var scanned []int
	_ = json.Unmarshal([]byte(portsJSON), &scanned)

	seen := r.FinishedAt.UTC()
	var alerts []model.Alert
	for _, a := range r.Assets {
		known, err := openPorts(ctx, tx, a.IP)
		if err != nil {
			return err
		}
		if known == nil {
			alerts = append(alerts, alert.NewAsset(a)...)
		} else {
			for _, p := range a.Ports {
				if !known[portKey{p.Port, p.Proto}] {
					alerts = append(alerts, alert.NewPort(a.IP, p))
				}
			}
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO assets (ip, hostname, probe_id, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE assets.hostname END,
				probe_id = excluded.probe_id,
				last_seen = excluded.last_seen`,
			a.IP, a.Hostname, r.ProbeID, seen, seen); err != nil {
			return err
		}
		// 本次扫描覆盖但没有出现在结果里的端口视为已关闭；未扫描的端口保留原状态。
		// 端口关闭后，该端口上的漏洞随之视为已修复。
		open := map[int]bool{}
		for _, p := range a.Ports {
			open[p.Port] = true
		}
		for _, port := range scanned {
			if _, err := tx.ExecContext(ctx, `DELETE FROM ports WHERE ip = ? AND proto = 'tcp' AND port = ?`, a.IP, port); err != nil {
				return err
			}
			if !open[port] {
				if err := fixVulns(ctx, tx, a.IP, port, "", seen); err != nil {
					return err
				}
			}
		}
		for _, p := range a.Ports {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO ports (ip, port, proto, service, banner, last_seen) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(ip, port, proto) DO UPDATE SET
					service = excluded.service, banner = excluded.banner, last_seen = excluded.last_seen`,
				a.IP, p.Port, p.Proto, p.Service, p.Banner, seen); err != nil {
				return err
			}
		}
	}

	// 蜜罐地址上的端口是伪装的，不产生资产变化告警
	if hp, err := honeypotIPs(ctx, tx); err != nil {
		return err
	} else if len(hp) > 0 {
		kept := alerts[:0]
		for _, al := range alerts {
			if !hp[al.IP] {
				kept = append(kept, al)
			}
		}
		alerts = kept
	}

	vulnAlerts, err := saveChecks(ctx, tx, append(r.Checks, vuln.CheckBanners(r.Assets)...), seen)
	if err != nil {
		return err
	}
	alerts = append(alerts, vulnAlerts...)

	if baseline {
		alerts = nil
	}
	for _, al := range alerts {
		if err := insertAlert(ctx, tx, al, seen); err != nil {
			return err
		}
	}

	status := model.TaskDone
	if r.Error != "" {
		status = model.TaskFailed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tasks SET status = ?, error = ?, updated_at = ? WHERE id = ?`,
		status, r.Error, time.Now().UTC(), r.TaskID); err != nil {
		return err
	}
	return tx.Commit()
}

type portKey struct {
	port  int
	proto string
}

// openPorts 返回资产当前记录的开放端口；资产不存在时返回 nil。
func openPorts(ctx context.Context, tx *Tx, ip string) (map[portKey]bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM assets WHERE ip = ?`, ip).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT port, proto FROM ports WHERE ip = ?`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	known := map[portKey]bool{}
	for rows.Next() {
		var k portKey
		if err := rows.Scan(&k.port, &k.proto); err != nil {
			return nil, err
		}
		known[k] = true
	}
	return known, rows.Err()
}

// ListAssets 返回所有资产及其开放端口。
func (s *Store) ListAssets(ctx context.Context) ([]model.Asset, error) {
	return s.queryAssets(ctx, ``)
}

func (s *Store) GetAsset(ctx context.Context, ip string) (model.Asset, error) {
	assets, err := s.queryAssets(ctx, `WHERE a.ip = ?`, ip)
	if err != nil {
		return model.Asset{}, err
	}
	if len(assets) == 0 {
		return model.Asset{}, ErrNotFound
	}
	return assets[0], nil
}

func (s *Store) queryAssets(ctx context.Context, where string, args ...any) ([]model.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.ip, a.hostname, a.probe_id, a.importance, a.owner, a.tags, a.first_seen, a.last_seen,
		       p.port, p.proto, p.service, p.banner
		FROM assets a
		LEFT JOIN ports p ON p.ip = a.ip
		`+where+`
		ORDER BY a.ip, p.port`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assets := []model.Asset{}
	for rows.Next() {
		var a model.Asset
		var port sql.NullInt64
		var proto, service, banner sql.NullString
		var tags string
		if err := rows.Scan(&a.IP, &a.Hostname, &a.ProbeID, &a.Importance, &a.Owner, &tags, &a.FirstSeen, &a.LastSeen,
			&port, &proto, &service, &banner); err != nil {
			return nil, err
		}
		if tags != "" {
			a.Tags = strings.Split(tags, ",")
		}
		if n := len(assets); n == 0 || assets[n-1].IP != a.IP {
			a.Ports = []model.Port{}
			assets = append(assets, a)
		}
		if port.Valid {
			last := &assets[len(assets)-1]
			last.Ports = append(last.Ports, model.Port{
				Port: int(port.Int64), Proto: proto.String, Service: service.String, Banner: banner.String,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hp, err := honeypotIPs(ctx, s.db)
	if err != nil {
		return nil, err
	}
	for i := range assets {
		assets[i].Honeypot = hp[assets[i].IP]
	}
	if err := s.scoreAssets(ctx, assets); err != nil {
		return nil, err
	}
	if err := s.annotateGroups(ctx, assets); err != nil {
		return nil, err
	}
	return assets, nil
}
