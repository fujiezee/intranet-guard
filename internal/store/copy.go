package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// copyTables 按外键依赖顺序排列；serial 表示 id 列为自增序列，复制后需要重置。
var copyTables = []struct {
	name   string
	serial bool
}{
	{"users", true}, {"sessions", false}, {"api_tokens", true},
	{"assets", false}, {"ports", false}, {"tasks", false},
	{"alerts", true}, {"agents", false}, {"host_events", true},
	{"ids_events", true}, {"ids_suppressions", true},
	{"enroll_tokens", true}, {"nodes", false}, {"vulns", true},
	{"notify_channels", true}, {"notify_cursor", false}, {"audit_log", true},
	{"honeypots", false}, {"honeypot_events", true}, {"simulations", false}, {"response_actions", false},
	{"incidents", true}, {"incident_notes", true}, {"asset_groups", true}, {"settings", false}, {"agent_upgrades", false},
	{"intel_indicators", true}, {"intel_feeds", true}, {"intel_meta", false},
}

// boolColumns 在 SQLite 里存为 0/1，写入 PostgreSQL 时转换为布尔值。
var boolColumns = map[string]bool{
	"tasks.baseline": true, "tasks.weak_password": true, "ids_events.suppressed": true,
	"notify_channels.enabled": true, "alerts.notified": true, "audit_log.success": true, "honeypots.enabled": true, "intel_feeds.enabled": true,
}

// CopyFrom 把 src（通常是 SQLite）中的全部数据复制到 s（通常是 PostgreSQL）。
// 目标库必须为空；整个复制在一个事务中完成，失败不会留下半份数据。返回每张表复制的行数。
func (s *Store) CopyFrom(ctx context.Context, src *Store) (map[string]int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, t := range copyTables {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t.name).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, fmt.Errorf("destination table %s is not empty; refusing to merge", t.name)
		}
	}

	counts := map[string]int{}
	for _, t := range copyTables {
		n, err := copyTable(ctx, src.db, tx, t.name)
		if err != nil {
			return nil, fmt.Errorf("copy %s: %w", t.name, err)
		}
		counts[t.name] = n
		if t.serial && s.db.d == dialectPostgres {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(
				`SELECT setval(pg_get_serial_sequence('%s', 'id'), COALESCE(MAX(id), 0) + 1, false) FROM %s`, t.name, t.name)); err != nil {
				return nil, fmt.Errorf("reset sequence %s: %w", t.name, err)
			}
		}
	}
	return counts, tx.Commit()
}

func copyTable(ctx context.Context, src *DB, dst *Tx, table string) (int, error) {
	rows, err := src.QueryContext(ctx, `SELECT * FROM `+table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
		marks[i] = "?"
	}
	stmt, err := dst.PrepareContext(ctx, dst.d.rebind(fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`,
		table, strings.Join(quoted, ", "), strings.Join(marks, ", "))))
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		for i, c := range cols {
			vals[i] = convertValue(vals[i], boolColumns[table+"."+c])
		}
		if _, err := stmt.ExecContext(ctx, vals...); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func convertValue(v any, isBool bool) any {
	switch x := v.(type) {
	case int64:
		if isBool {
			return x != 0
		}
	case time.Time:
		return x.UTC()
	case []byte:
		return string(x)
	}
	return v
}
