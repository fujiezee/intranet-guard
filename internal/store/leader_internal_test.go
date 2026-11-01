package store

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// 请求处理的连接池被占满（高负载）时，备用实例仍然要能接手主实例。
func TestLeaderTakeoverUnderPoolExhaustion(t *testing.T) {
	dsn := os.Getenv("SAFE_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("needs PostgreSQL (SAFE_TEST_PG_DSN)")
	}
	schema := "leader_" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	admin, _ := sql.Open("pgx", dsn)
	defer admin.Close()
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	u, _ := url.Parse(dsn)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	a, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	la, lb := a.NewLeader(), b.NewLeader()
	la.Interval, lb.Interval = 50*time.Millisecond, 50*time.Millisecond
	ctxA, stopA := context.WithCancel(context.Background())
	go la.Run(ctxA)
	wait := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if cond() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("timeout: " + what)
	}
	wait("A leads", la.IsLeader)

	// 占满 B 的请求连接池
	var held []*sql.Conn
	for i := 0; i < 20; i++ {
		c, err := b.db.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	go lb.Run(ctxB)
	stopA()
	wait("B takes over while its request pool is exhausted", lb.IsLeader)
}
