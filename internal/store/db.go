package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// rebind 把 SQL 中的 ? 占位符改写为 PostgreSQL 的 $1、$2…；单引号字符串内的 ? 不处理。
func (d dialect) rebind(q string) string {
	if d != dialectPostgres || !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n, inQuote := 0, false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'':
			inQuote = !inQuote
		case c == '?' && !inQuote:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// DB 包装 *sql.DB，在执行前按方言改写占位符，业务代码统一使用 ? 写 SQL。
type DB struct {
	*sql.DB
	d dialect
}

func (db *DB) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, db.d.rebind(q), args...)
}

func (db *DB) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.d.rebind(q), args...)
}

func (db *DB) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.d.rebind(q), args...)
}

func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := db.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, d: db.d}, nil
}

// querier 是 *DB 和 *Tx 共有的查询方法，供既可在事务内也可在事务外调用的辅助函数使用。
type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

type Tx struct {
	*sql.Tx
	d dialect
}

func (tx *Tx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, tx.d.rebind(q), args...)
}

func (tx *Tx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return tx.Tx.QueryContext(ctx, tx.d.rebind(q), args...)
}

func (tx *Tx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, tx.d.rebind(q), args...)
}

// schemaFor 把以 SQLite 语法书写的建表语句转换为目标数据库的语法。
func schemaFor(d dialect) string {
	if d != dialectPostgres {
		return schema
	}
	return strings.NewReplacer(
		"INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY",
		"INTEGER", "BIGINT", // unix 毫秒时间戳等超出 int4 范围
		"TIMESTAMP", "TIMESTAMPTZ",
	).Replace(schema)
}
