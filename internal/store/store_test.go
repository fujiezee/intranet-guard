package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/netintel"
	"safe/internal/store"
	"safe/internal/store/storetest"
)

// 并发领取：每个任务只能被领取一次。
func TestConcurrentClaim(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	const tasks = 50
	for i := 0; i < tasks; i++ {
		now := time.Now().UTC()
		st.CreateTask(ctx, model.ScanTask{ID: fmt.Sprintf("t%02d", i), ProbeID: "seg-a", Targets: []string{"10.0.0.1"},
			Ports: []int{22}, Status: model.TaskPending, CreatedAt: now, UpdatedAt: now})
	}
	var mu sync.Mutex
	claimed := map[string]int{}
	var wg sync.WaitGroup
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				got, err := st.ClaimTasks(ctx, "seg-a")
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				for _, tk := range got {
					claimed[tk.ID]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimed) != tasks {
		t.Errorf("claimed %d distinct tasks, want %d", len(claimed), tasks)
	}
	for id, n := range claimed {
		if n != 1 {
			t.Errorf("task %s claimed %d times", id, n)
		}
	}
}

// 并发注册：令牌不会超出 max_uses，同一 ID 只能注册成功一次。
func TestConcurrentEnroll(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	st.CreateEnrollToken(ctx, model.EnrollToken{Kind: model.NodeAgent, MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour),
		CreatedBy: "test"}, "hash")
	sign := func() (string, time.Time, error) {
		return fmt.Sprint(time.Now().UnixNano()), time.Now().Add(time.Hour), nil
	}

	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := st.Enroll(ctx, "hash", model.NodeAgent, fmt.Sprintf("host%02d", i), sign); err == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Errorf("%d enrollments succeeded, want 5", ok.Load())
	}

	st.CreateEnrollToken(ctx, model.EnrollToken{Kind: model.NodeAgent, MaxUses: 100, ExpiresAt: time.Now().Add(time.Hour),
		CreatedBy: "test"}, "hash2")
	ok.Store(0)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.Enroll(ctx, "hash2", model.NodeAgent, "same-host", sign); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("same id enrolled %d times, want 1", ok.Load())
	}
	tokens, _ := st.ListEnrollTokens(ctx)
	for _, tk := range tokens {
		if tk.Uses > tk.MaxUses {
			t.Errorf("token %d used %d > %d", tk.ID, tk.Uses, tk.MaxUses)
		}
	}
}

// 迁移：SQLite 数据完整复制，自增序列在复制后继续可用。
func TestCopyFrom(t *testing.T) {
	ctx := context.Background()
	src, err := store.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	now := time.Now().UTC()
	src.CreateUser(ctx, "admin", "hash", model.RoleAdmin)
	src.CreateTask(ctx, model.ScanTask{ID: "t1", ProbeID: "seg-a", Targets: []string{"10.0.0.1"}, Ports: []int{22, 6379},
		Baseline: true, Status: model.TaskPending, CreatedAt: now, UpdatedAt: now})
	src.ClaimTasks(ctx, "seg-a")
	src.SaveReport(ctx, model.ScanReport{TaskID: "t1", ProbeID: "seg-a", FinishedAt: now,
		Assets: []model.Asset{{IP: "10.0.0.1", Ports: []model.Port{{Port: 22, Proto: "tcp", Banner: "SSH-2.0"}}}}})
	src.SaveAgentReport(ctx, model.AgentReport{Agent: model.AgentInfo{ID: "web01", IPs: []string{"10.0.0.1"}},
		Events: []model.HostEvent{{Type: model.EventLoginSuccess, Time: now, User: "root", SrcIP: "10.0.0.9"}}})
	src.SaveIDSReport(ctx, model.IDSReport{ProbeID: "seg-a", Events: []model.IDSEvent{{Time: now, SrcIP: "1.2.3.4",
		DestIP: "10.0.0.1", SignatureID: 1, Signature: "x", Severity: 1}}})

	dst := storetest.Open(t)
	counts, err := dst.CopyFrom(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{"users": 1, "tasks": 1, "assets": 1, "ports": 1, "host_events": 1, "ids_events": 1, "alerts": 2} {
		if counts[table] != want {
			t.Errorf("%s: copied %d rows, want %d", table, counts[table], want)
		}
	}
	task, err := dst.GetTask(ctx, "t1")
	if err != nil || !task.Baseline || task.Status != model.TaskDone || len(task.Ports) != 2 {
		t.Errorf("task = %+v, %v", task, err)
	}
	a, err := dst.GetAsset(ctx, "10.0.0.1")
	if err != nil || len(a.Ports) != 1 || a.Ports[0].Banner != "SSH-2.0" {
		t.Errorf("asset = %+v, %v", a, err)
	}
	// 序列已重置：新插入的行不会与复制过来的 id 冲突。
	if u, err := dst.CreateUser(ctx, "alice", "hash", model.RoleViewer); err != nil || u.ID != 2 {
		t.Errorf("new user after copy: %+v, %v", u, err)
	}
	// 目标非空时拒绝再次复制。
	if _, err := dst.CopyFrom(ctx, src); err == nil {
		t.Error("copy into non-empty destination should fail")
	}
}

type captureEvents struct {
	store.EventStore
	hosts map[string]int
	ids   map[string]int
	calls int
}

func (c *captureEvents) InsertHostEvents(_ context.Context, agent string, ev []model.HostEvent) error {
	c.hosts[agent] += len(ev)
	c.calls++
	return nil
}

func (c *captureEvents) InsertIDSEvents(_ context.Context, probe string, ev []model.IDSEvent) error {
	c.ids[probe] += len(ev)
	c.calls++
	return nil
}

// 导出历史事件：按 Agent / 探针分组、按批次写入，条数完整。导出的来源固定是主库。
func TestExportEvents(t *testing.T) {
	ctx := context.Background()
	st := storetest.OpenMain(t)
	for _, agent := range []string{"web01", "db01"} {
		var events []model.HostEvent
		for i := 0; i < 7; i++ {
			events = append(events, model.HostEvent{Type: model.EventSudo, Time: time.Now(), User: "u"})
		}
		st.SaveAgentReport(ctx, model.AgentReport{Agent: model.AgentInfo{ID: agent}, Events: events})
	}
	st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "seg-a", Events: []model.IDSEvent{
		{Time: time.Now(), SrcIP: "1.1.1.1", DestIP: "10.0.0.1", SignatureID: 1, Severity: 3, Suppressed: true}}})

	dst := &captureEvents{hosts: map[string]int{}, ids: map[string]int{}}
	hosts, ids, err := st.ExportEvents(ctx, dst, 3)
	if err != nil {
		t.Fatal(err)
	}
	if hosts != 14 || ids != 1 || dst.hosts["web01"] != 7 || dst.hosts["db01"] != 7 || dst.ids["seg-a"] != 1 {
		t.Errorf("exported hosts=%d ids=%d dst=%+v", hosts, ids, dst)
	}
	if dst.calls != 3+3+1 { // 每个 Agent 7 条按 3 条一批 = 3 批
		t.Errorf("insert calls = %d", dst.calls)
	}
}

// 情报分批插入：跨批次的重复条目不重复计数，订阅源刷新整体替换旧条目。
func TestIntelBatchInsert(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	ips := func(from, to int) []netintel.Indicator {
		var out []netintel.Indicator
		for i := from; i < to; i++ {
			out = append(out, netintel.Indicator{Type: "ip", Value: fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)})
		}
		return out
	}
	if n, err := st.AddIndicators(ctx, model.SeverityHigh, "", ips(0, 1203)); err != nil || n != 1203 {
		t.Fatalf("added %d, %v", n, err)
	}
	if n, err := st.AddIndicators(ctx, model.SeverityHigh, "", ips(700, 1800)); err != nil || n != 1800-1203 {
		t.Fatalf("re-add: added %d, %v", n, err)
	}
	f, err := st.CreateFeed(ctx, model.IntelFeed{Name: "f", URL: "https://example.com/f.txt", Severity: model.SeverityMedium, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]netintel.Indicator{ips(0, 1001), ips(2000, 2600)} {
		if err := st.RecordFeedFetch(ctx, f.ID, list, nil); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := st.IntelCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["manual"] != 1800 || counts[fmt.Sprintf("feed:%d", f.ID)] != 600 {
		t.Errorf("counts = %v", counts)
	}
	feeds, _ := st.ListFeeds(ctx)
	if len(feeds) != 1 || feeds[0].Count != 600 {
		t.Errorf("feed count = %+v", feeds)
	}
}
