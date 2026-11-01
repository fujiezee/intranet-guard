package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"safe/internal/store/storetest"
)

func TestLeaderElection(t *testing.T) {
	sts := storetest.OpenShared(t, 2)
	a, b := sts[0].NewLeader(), sts[1].NewLeader()
	if os.Getenv("SAFE_TEST_PG_DSN") == "" {
		if !a.IsLeader() || !b.IsLeader() {
			t.Error("SQLite (single instance) should always be leader")
		}
		return
	}
	a.Interval, b.Interval = 50*time.Millisecond, 50*time.Millisecond
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	go a.Run(ctxA)
	waitFor(t, "first instance becomes leader", a.IsLeader)
	go b.Run(ctxB)
	time.Sleep(300 * time.Millisecond)
	if b.IsLeader() {
		t.Fatal("two leaders at the same time")
	}

	// 主实例退出（释放锁）→ 另一实例接手
	stopA()
	waitFor(t, "second instance takes over", b.IsLeader)
	if a.IsLeader() {
		t.Error("stopped instance still reports leader")
	}

	// 其他 schema 中的独立部署不受影响
	other := storetest.OpenShared(t, 1)[0].NewLeader()
	other.Interval = 50 * time.Millisecond
	ctxO, stopO := context.WithCancel(context.Background())
	defer stopO()
	go other.Run(ctxO)
	waitFor(t, "deployment in another schema has its own leader", other.IsLeader)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}
