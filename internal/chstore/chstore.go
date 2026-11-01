// Package chstore 把主机事件和 IDS 事件存到 ClickHouse，用于上千台主机规模的事件量。
// 通过 ClickHouse 的 HTTP 接口通信（不引入额外依赖），查询参数使用服务端参数绑定，不拼接 SQL。
package chstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/store"
)

type Store struct {
	base     string // http(s)://host:port/
	database string
	user     string
	password string
	http     *http.Client
}

// Open 连接 ClickHouse 并建表。dsn 形如 clickhouse://user:password@host:8123/dbname
// （clickhouses:// 使用 HTTPS）。retention 为事件保留时长，由 ClickHouse TTL 自动清理。
func Open(ctx context.Context, dsn string, retention time.Duration) (*Store, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	scheme := map[string]string{"clickhouse": "http", "clickhouses": "https"}[u.Scheme]
	if scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("events DSN must look like clickhouse://user:pass@host:8123/dbname")
	}
	s := &Store{
		base:     scheme + "://" + u.Host + "/",
		database: strings.Trim(u.Path, "/"),
		http:     &http.Client{Timeout: 60 * time.Second},
	}
	if s.database == "" {
		s.database = "safe"
	}
	if u.User != nil {
		s.user = u.User.Username()
		s.password, _ = u.User.Password()
	}

	days := int(retention.Hours() / 24)
	if days < 1 {
		days = 1
	}
	stmts := []string{
		"CREATE DATABASE IF NOT EXISTS " + quoteIdent(s.database),
		`CREATE TABLE IF NOT EXISTS host_events (
			ts       DateTime64(3, 'UTC'),
			agent_id LowCardinality(String),
			type     LowCardinality(String),
			user     String,
			src_ip   String,
			path     String,
			detail   String
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(ts)
		ORDER BY (agent_id, type, src_ip, ts)
		TTL toDateTime(ts) + INTERVAL ` + strconv.Itoa(days) + ` DAY`,
		`CREATE TABLE IF NOT EXISTS ids_events (
			ts           DateTime64(3, 'UTC'),
			probe_id     LowCardinality(String),
			src_ip       String,
			src_port     UInt16,
			dest_ip      String,
			dest_port    UInt16,
			proto        LowCardinality(String),
			app_proto    LowCardinality(String),
			signature_id UInt64,
			signature    String,
			category     LowCardinality(String),
			severity     UInt8,
			action       LowCardinality(String),
			suppressed   Bool
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(ts)
		ORDER BY (ts, src_ip, dest_ip)
		TTL toDateTime(ts) + INTERVAL ` + strconv.Itoa(days) + ` DAY`,
	}
	for i, q := range stmts {
		db := s.database
		if i == 0 {
			db = "default" // 建库语句不能在尚不存在的库里执行
		}
		if _, err := s.do(ctx, db, q, nil, nil); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// DropDatabase 删除整个库，仅用于测试清理。
func (s *Store) DropDatabase(ctx context.Context) error {
	_, err := s.do(ctx, "default", "DROP DATABASE IF EXISTS "+quoteIdent(s.database), nil, nil)
	return err
}

func quoteIdent(name string) string { return "`" + strings.ReplaceAll(name, "`", "") + "`" }

// do 执行一条语句。params 通过 param_<name> 传给服务端参数绑定（SQL 中写作 {name:Type}）；
// data 非空时作为 INSERT 的数据体，此时语句放在 URL 上。
func (s *Store) do(ctx context.Context, database, query string, params map[string]string, data []byte) ([]byte, error) {
	v := url.Values{}
	v.Set("database", database)
	// 64 位整数默认会被加引号输出，关闭以便直接解析为数字。
	v.Set("output_format_json_quote_64bit_integers", "0")
	for k, p := range params {
		v.Set("param_"+k, p)
	}
	body := []byte(query)
	if data != nil {
		v.Set("query", query)
		body = data
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"?"+v.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if s.user != "" {
		req.Header.Set("X-ClickHouse-User", s.user)
		req.Header.Set("X-ClickHouse-Key", s.password)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clickhouse: %s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func chTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }

func (s *Store) insert(ctx context.Context, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	_, err := s.do(context.WithoutCancel(ctx), s.database, "INSERT INTO "+table+" FORMAT JSONEachRow", nil, buf.Bytes())
	return err
}

func (s *Store) InsertHostEvents(ctx context.Context, agentID string, events []model.HostEvent) error {
	rows := make([]any, len(events))
	for i, ev := range events {
		rows[i] = map[string]any{
			"ts": chTime(ev.Time), "agent_id": agentID, "type": ev.Type, "user": ev.User,
			"src_ip": ev.SrcIP, "path": ev.Path, "detail": ev.Detail,
		}
	}
	return s.insert(ctx, "host_events", rows)
}

func (s *Store) InsertIDSEvents(ctx context.Context, probeID string, events []model.IDSEvent) error {
	rows := make([]any, len(events))
	for i, ev := range events {
		rows[i] = map[string]any{
			"ts": chTime(ev.Time), "probe_id": probeID, "src_ip": ev.SrcIP, "src_port": ev.SrcPort,
			"dest_ip": ev.DestIP, "dest_port": ev.DestPort, "proto": ev.Proto, "app_proto": ev.AppProto,
			"signature_id": ev.SignatureID, "signature": ev.Signature, "category": ev.Category,
			"severity": ev.Severity, "action": ev.Action, "suppressed": ev.Suppressed,
		}
	}
	return s.insert(ctx, "ids_events", rows)
}

func (s *Store) CountLoginFailures(ctx context.Context, agentID, srcIP string, from, to time.Time) (int, error) {
	out, err := s.do(ctx, s.database, `
		SELECT count() AS n FROM host_events
		WHERE agent_id = {agent:String} AND type = {type:String} AND src_ip = {src:String}
		  AND ts BETWEEN fromUnixTimestamp64Milli({from:Int64}) AND fromUnixTimestamp64Milli({to:Int64})
		FORMAT JSONEachRow`, map[string]string{
		"agent": agentID, "type": string(model.EventLoginFailed), "src": srcIP,
		"from": strconv.FormatInt(from.UnixMilli(), 10), "to": strconv.FormatInt(to.UnixMilli(), 10),
	}, nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		N int `json:"n"`
	}
	err = json.Unmarshal(out, &r)
	return r.N, err
}

func (s *Store) LoginTargets(ctx context.Context, srcIP string, from, to time.Time) ([]string, error) {
	out, err := s.do(ctx, s.database, `
		SELECT DISTINCT agent_id FROM host_events
		WHERE type = {type:String} AND src_ip = {src:String}
		  AND ts BETWEEN fromUnixTimestamp64Milli({from:Int64}) AND fromUnixTimestamp64Milli({to:Int64})
		LIMIT 1000 FORMAT JSONEachRow`, map[string]string{
		"type": string(model.EventLoginSuccess), "src": srcIP,
		"from": strconv.FormatInt(from.UnixMilli(), 10), "to": strconv.FormatInt(to.UnixMilli(), 10),
	}, nil)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		ids = append(ids, r.AgentID)
	}
	return ids, nil
}

func (s *Store) ListHostEvents(ctx context.Context, f store.EventFilter) ([]model.HostEvent, error) {
	from, to := f.Bounds()
	if to > 253402300799000 { // ClickHouse DateTime64 上限（9999 年）
		to = 253402300799000
	}
	out, err := s.do(ctx, s.database, `
		SELECT toUnixTimestamp64Milli(ts) AS ts_ms, agent_id, type, user, src_ip, path, detail FROM host_events
		WHERE ({agent:String} = '' OR agent_id = {agent:String})
		  AND ({type:String} = '' OR type = {type:String})
		  AND ({src:String} = '' OR src_ip = {src:String})
		  AND ts BETWEEN fromUnixTimestamp64Milli({from:Int64}) AND fromUnixTimestamp64Milli({to:Int64})
		ORDER BY ts DESC LIMIT {limit:UInt32}
		FORMAT JSONEachRow`, map[string]string{
		"agent": f.AgentID, "type": string(f.Type), "src": f.SrcIP, "limit": strconv.Itoa(f.Limit),
		"from": strconv.FormatInt(from, 10), "to": strconv.FormatInt(to, 10),
	}, nil)
	if err != nil {
		return nil, err
	}
	events := []model.HostEvent{}
	err = eachRow(out, func(dec func(any) error) error {
		var r struct {
			TsMs int64 `json:"ts_ms"`
			model.HostEvent
		}
		if err := dec(&r); err != nil {
			return err
		}
		r.HostEvent.Time = time.UnixMilli(r.TsMs).UTC()
		events = append(events, r.HostEvent)
		return nil
	})
	return events, err
}

func (s *Store) ListIDSEvents(ctx context.Context, f store.IDSFilter) ([]model.IDSEvent, error) {
	out, err := s.do(ctx, s.database, `
		SELECT toUnixTimestamp64Milli(ts) AS ts_ms, probe_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
		       signature_id, signature, category, severity, action, suppressed
		FROM ids_events
		WHERE ({probe:String} = '' OR probe_id = {probe:String})
		  AND ({src:String} = '' OR src_ip = {src:String})
		  AND ({dest:String} = '' OR dest_ip = {dest:String})
		  AND ({sid:UInt64} = 0 OR signature_id = {sid:UInt64})
		  AND ({maxsev:UInt8} = 0 OR severity <= {maxsev:UInt8})
		ORDER BY ts DESC LIMIT {limit:UInt32}
		FORMAT JSONEachRow`, map[string]string{
		"probe": f.ProbeID, "src": f.SrcIP, "dest": f.DestIP, "sid": strconv.FormatInt(f.SignatureID, 10),
		"maxsev": strconv.Itoa(f.MaxSeverity), "limit": strconv.Itoa(f.Limit),
	}, nil)
	if err != nil {
		return nil, err
	}
	events := []model.IDSEvent{}
	err = eachRow(out, func(dec func(any) error) error {
		var r struct {
			TsMs int64 `json:"ts_ms"`
			model.IDSEvent
		}
		if err := dec(&r); err != nil {
			return err
		}
		r.IDSEvent.Time = time.UnixMilli(r.TsMs).UTC()
		events = append(events, r.IDSEvent)
		return nil
	})
	return events, err
}

// Purge 是空操作：过期数据由表上的 TTL 自动清理。
func (s *Store) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func eachRow(out []byte, fn func(dec func(any) error) error) error {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := fn(func(v any) error { return json.Unmarshal(line, v) }); err != nil {
			return err
		}
	}
	return sc.Err()
}

var _ store.EventStore = (*Store)(nil)

// Count 返回两张事件表的总行数，用于导入前确认目标为空。
func (s *Store) Count(ctx context.Context) (int64, error) {
	out, err := s.do(ctx, s.database,
		`SELECT (SELECT count() FROM host_events) + (SELECT count() FROM ids_events) AS n FORMAT JSONEachRow`, nil, nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		N int64 `json:"n"`
	}
	err = json.Unmarshal(out, &r)
	return r.N, err
}
