package store

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/netintel"
)

// SimIntelDomain 是内置的自检情报域名：攻击模拟自检查询它的子域名，验证探针能看到 DNS 并完成情报匹配。
// example.com 是保留域名，查询只会得到“不存在”。
const SimIntelDomain = "safe-sim.example.com"

const SourceManual = "manual"

func feedSource(id int64) string { return fmt.Sprintf("feed:%d", id) }

// bumpIntel 递增情报版本号，探针据此判断是否需要重新拉取。
func bumpIntel(ctx context.Context, tx *Tx) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO intel_meta (id, version, net_config) VALUES (1, 1, '')
		ON CONFLICT(id) DO UPDATE SET version = intel_meta.version + 1`)
	return err
}

func (s *Store) IntelVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, `SELECT version FROM intel_meta WHERE id = 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// insertIndicators 插入情报（同一来源的重复条目忽略），返回新增数量。
func insertIndicators(ctx context.Context, tx *Tx, source string, sev model.Severity, note string, list []netintel.Indicator) (int, error) {
	now := time.Now().UTC()
	added := 0
	for _, ind := range list {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO intel_indicators (type, value, source, severity, note, created_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(source, type, value) DO NOTHING`, ind.Type, ind.Value, source, sev, note, now)
		if err != nil {
			return added, err
		}
		n, _ := res.RowsAffected()
		added += int(n)
	}
	return added, nil
}

// AddIndicators 添加手工情报。
func (s *Store) AddIndicators(ctx context.Context, sev model.Severity, note string, list []netintel.Indicator) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	added, err := insertIndicators(ctx, tx, SourceManual, sev, note, list)
	if err != nil {
		return 0, err
	}
	if err := bumpIntel(ctx, tx); err != nil {
		return 0, err
	}
	return added, tx.Commit()
}

func (s *Store) DeleteIndicator(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM intel_indicators WHERE id = ? AND source = ?`, id, SourceManual)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := bumpIntel(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ListIndicators 按值模糊查询（q 为空时列出最近添加的）。
func (s *Store) ListIndicators(ctx context.Context, q string, limit int) ([]model.IntelIndicator, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, value, source, severity, note, created_at FROM intel_indicators
		WHERE ? = '' OR value LIKE ? ORDER BY id DESC LIMIT ?`, q, "%"+q+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.IntelIndicator{}
	for rows.Next() {
		var i model.IntelIndicator
		if err := rows.Scan(&i.ID, &i.Type, &i.Value, &i.Source, &i.Severity, &i.Note, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// IntelCounts 返回各来源的条目数。
func (s *Store) IntelCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, COUNT(*) FROM intel_indicators GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, err
		}
		out[src] = n
	}
	return out, rows.Err()
}

// AllIndicators 返回下发给探针的全部情报（只含启用的订阅源），附带内置的自检域名。
func (s *Store) AllIndicators(ctx context.Context) ([]netintel.Indicator, error) {
	// 先查订阅源名称：SQLite 只有一个连接，遍历查询结果期间不能再发起查询
	names := map[int64]string{}
	feeds, err := s.ListFeeds(ctx)
	if err != nil {
		return nil, err
	}
	for _, f := range feeds {
		names[f.ID] = f.Name
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.type, i.value, i.source, i.severity, i.note FROM intel_indicators i
		LEFT JOIN intel_feeds f ON i.source = 'feed:' || CAST(f.id AS TEXT)
		WHERE i.source = ? OR f.enabled = ?`, SourceManual, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []netintel.Indicator{{Type: "domain", Value: SimIntelDomain, Source: "内置自检", Severity: "high", Note: "攻击模拟自检使用"}}
	for rows.Next() {
		var ind netintel.Indicator
		if err := rows.Scan(&ind.Type, &ind.Value, &ind.Source, &ind.Severity, &ind.Note); err != nil {
			return nil, err
		}
		var id int64
		if _, err := fmt.Sscanf(ind.Source, "feed:%d", &id); err == nil && names[id] != "" {
			ind.Source = names[id]
		} else if ind.Source == SourceManual {
			ind.Source = "自定义"
		}
		out = append(out, ind)
	}
	return out, rows.Err()
}

// --- 订阅源 ---

func (s *Store) ListFeeds(ctx context.Context) ([]model.IntelFeed, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, url, severity, enabled, count, last_fetch, last_error FROM intel_feeds ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.IntelFeed{}
	for rows.Next() {
		var f model.IntelFeed
		var last sql.NullTime
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.Severity, &f.Enabled, &f.Count, &last, &f.LastError); err != nil {
			return nil, err
		}
		if last.Valid {
			f.LastFetch = &last.Time
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CreateFeed(ctx context.Context, f model.IntelFeed) (model.IntelFeed, error) {
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO intel_feeds (name, url, severity, enabled, count, last_error) VALUES (?, ?, ?, ?, 0, '') RETURNING id`,
		f.Name, f.URL, f.Severity, f.Enabled).Scan(&f.ID)
	return f, err
}

// SetFeedEnabled 启用 / 停用订阅源；停用的订阅源不下发给探针。
func (s *Store) SetFeedEnabled(ctx context.Context, id int64, enabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE intel_feeds SET enabled = ? WHERE id = ?`, enabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := bumpIntel(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteFeed(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM intel_feeds WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM intel_indicators WHERE source = ?`, feedSource(id)); err != nil {
		return err
	}
	if err := bumpIntel(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordFeedFetch 用一次拉取的结果替换该订阅源的全部条目；fetchErr 非空时保留旧条目，只记录错误。
func (s *Store) RecordFeedFetch(ctx context.Context, id int64, list []netintel.Indicator, fetchErr error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if fetchErr != nil {
		_, err := tx.ExecContext(ctx, `UPDATE intel_feeds SET last_fetch = ?, last_error = ? WHERE id = ?`, now, fetchErr.Error(), id)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	var sev model.Severity
	if err := tx.QueryRowContext(ctx, `SELECT severity FROM intel_feeds WHERE id = ?`, id).Scan(&sev); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM intel_indicators WHERE source = ?`, feedSource(id)); err != nil {
		return err
	}
	n, err := insertIndicators(ctx, tx, feedSource(id), sev, "", list)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE intel_feeds SET last_fetch = ?, last_error = '', count = ? WHERE id = ?`, now, n, id); err != nil {
		return err
	}
	if err := bumpIntel(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// FeedsDue 返回需要拉取的订阅源（启用且超过 every 未拉取）。
func (s *Store) FeedsDue(ctx context.Context, every time.Duration) ([]model.IntelFeed, error) {
	feeds, err := s.ListFeeds(ctx)
	if err != nil {
		return nil, err
	}
	var due []model.IntelFeed
	for _, f := range feeds {
		if f.Enabled && (f.LastFetch == nil || time.Since(*f.LastFetch) > every) {
			due = append(due, f)
		}
	}
	return due, nil
}

// --- 分析参数 ---

func (s *Store) NetConfig(ctx context.Context) (netintel.Config, error) {
	cfg := netintel.DefaultConfig()
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT net_config FROM intel_meta WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || raw == "" {
		return cfg, nil
	} else if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal([]byte(raw), &cfg)
}

func (s *Store) SetNetConfig(ctx context.Context, cfg netintel.Config) error {
	raw, _ := json.Marshal(cfg)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := bumpIntel(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE intel_meta SET net_config = ? WHERE id = 1`, string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

// --- 解析 ---

var reDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?)+$`)

// ParseIndicator 识别一个值是 IP、网段还是域名。
func ParseIndicator(v string) (netintel.Indicator, bool) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() || a.IsPrivate() {
			return netintel.Indicator{}, false // hosts 文件的 0.0.0.0 / 127.0.0.1 前缀、内网地址不作为情报
		}
		return netintel.Indicator{Type: "ip", Value: a.String()}, true
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		if p.Bits() < 8 { // 太大的网段几乎必然误报
			return netintel.Indicator{}, false
		}
		return netintel.Indicator{Type: "cidr", Value: p.Masked().String()}, true
	}
	if d := netintel.NormalizeDomain(v); d != "" && reDomain.MatchString(d) && d != "localhost" {
		return netintel.Indicator{Type: "domain", Value: d}, true
	}
	return netintel.Indicator{}, false
}

// ParseIntelList 解析纯文本情报：每行一个，支持 # / ; 注释、hosts 文件格式（"0.0.0.0 evil.com"）和 CSV 的第一列。
func ParseIntelList(r io.Reader, max int) ([]netintel.Indicator, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	var out []netintel.Indicator
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '"' }) {
			ind, ok := ParseIndicator(field)
			if !ok || seen[ind.Type+ind.Value] {
				continue
			}
			seen[ind.Type+ind.Value] = true
			out = append(out, ind)
			if len(out) > max {
				return nil, fmt.Errorf("more than %d indicators", max)
			}
			break // 每行只取一个：hosts 格式第一个字段（回环地址）已被跳过
		}
	}
	return out, sc.Err()
}

// --- 管理中心侧的情报匹配（登录来源、IDS 告警中的地址）---

type intelCache struct {
	mu      sync.Mutex
	version int64
	intel   *netintel.Intel
}

// intelSnapshot 返回当前情报集合；版本未变时复用缓存。必须在开启事务之前调用（SQLite 只有一个连接）。
func (s *Store) intelSnapshot(ctx context.Context) (*netintel.Intel, error) {
	v, err := s.IntelVersion(ctx)
	if err != nil {
		return nil, err
	}
	s.intel.mu.Lock()
	defer s.intel.mu.Unlock()
	if s.intel.intel != nil && s.intel.version == v {
		return s.intel.intel, nil
	}
	list, err := s.AllIndicators(ctx)
	if err != nil {
		return nil, err
	}
	s.intel.intel, s.intel.version = netintel.NewIntel(list), v
	return s.intel.intel, nil
}

// SaveNetFindings 把探针的网络分析结果转为告警，关联到内网中的相关主机。
func (s *Store) SaveNetFindings(ctx context.Context, probeID string, findings []netintel.Finding) error {
	if len(findings) > MaxEventsPerReport {
		return ErrTooManyEvents
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, f := range findings {
		if err := insertDedupAlert(ctx, tx, alert.NetFinding(probeID, f), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
