// Package storetest 为测试提供独立的数据库：设置 SAFE_TEST_PG_DSN 时在 PostgreSQL 中为每个测试
// 创建独立 schema，否则使用临时 SQLite 文件。设置 SAFE_TEST_CH_URL（clickhouse://…）时事件存到
// ClickHouse 中为每个测试单独创建的库。
package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"safe/internal/chstore"
	"safe/internal/store"
)

func Open(t *testing.T) *store.Store {
	t.Helper()
	st := OpenMain(t)
	if ch := os.Getenv("SAFE_TEST_CH_URL"); ch != "" {
		u, err := url.Parse(ch)
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + randName()
		es, err := chstore.Open(context.Background(), u.String(), 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { es.DropDatabase(context.Background()) })
		st.UseEventStore(es)
	}
	return st
}

func randName() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "test_" + hex.EncodeToString(b)
}

// OpenMain 只打开主库（SQLite 或 SAFE_TEST_PG_DSN 指定的 PostgreSQL），事件也存在主库，不接 ClickHouse。
func OpenMain(t *testing.T) *store.Store {
	return OpenShared(t, 1)[0]
}

// OpenShared 打开 n 个共用同一数据库（同一 schema 或同一 SQLite 文件）的 Store，模拟多个管理中心实例。
func OpenShared(t *testing.T, n int) []*store.Store {
	t.Helper()
	dsn := os.Getenv("SAFE_TEST_PG_DSN")
	if dsn == "" {
		path := filepath.Join(t.TempDir(), "test.db")
		var out []*store.Store
		for i := 0; i < n; i++ {
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			out = append(out, st)
		}
		return out
	}

	schema := randName()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	var out []*store.Store
	for i := 0; i < n; i++ {
		st, err := store.Open(u.String())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, st)
	}
	t.Cleanup(func() {
		for _, st := range out {
			st.Close()
		}
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		admin.Close()
	})
	return out
}
