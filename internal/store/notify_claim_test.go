package store_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/store/storetest"
)

func TestClaimPendingAlerts(t *testing.T) {
	ctx := context.Background()
	sts := storetest.OpenShared(t, 2) // 两个管理中心实例共用一个数据库
	a, b := sts[0], sts[1]

	// 已有的告警全部处理掉，从干净的状态开始
	for {
		got, _ := a.ClaimPendingAlerts(ctx, 1000, time.Minute)
		if len(got) == 0 {
			break
		}
		ids := []int64{}
		for _, x := range got {
			ids = append(ids, x.ID)
		}
		a.MarkNotified(ctx, ids)
	}
	var events []model.IDSEvent
	for i := 0; i < 200; i++ {
		events = append(events, model.IDSEvent{Time: time.Now(), SrcIP: fmt.Sprintf("10.66.%d.%d", i/250, i%250), DestIP: "10.0.0.1",
			SignatureID: int64(1000 + i), Signature: fmt.Sprintf("sig %d", i), Severity: 1})
	}
	if err := a.SaveIDSReport(ctx, model.IDSReport{ProbeID: "p", Events: events}); err != nil {
		t.Fatal(err)
	}

	// 并发领取：两个实例各 4 个推送方，每次领 7 条，领到的互不重叠且合起来是全部
	seen := map[int64]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		st := sts[w%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				got, err := st.ClaimPendingAlerts(ctx, 7, time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if len(got) == 0 {
					return
				}
				ids := []int64{}
				mu.Lock()
				for i, x := range got {
					seen[x.ID]++
					ids = append(ids, x.ID)
					if i > 0 && got[i-1].ID >= x.ID {
						t.Error("claimed alerts not sorted by id")
					}
				}
				mu.Unlock()
				st.MarkNotified(ctx, ids)
			}
		}()
	}
	wg.Wait()
	dup := 0
	for _, n := range seen {
		if n > 1 {
			dup++
		}
	}
	if len(seen) < 200 || dup > 0 {
		t.Fatalf("claimed %d distinct alerts, %d claimed more than once", len(seen), dup)
	}

	// 领取后宕机（没有标记已推送）：租约内别人领不到，租约过期后重新领取
	a.SaveIDSReport(ctx, model.IDSReport{ProbeID: "p", Events: []model.IDSEvent{
		{Time: time.Now(), SrcIP: "10.77.0.1", DestIP: "10.0.0.1", SignatureID: 9999, Signature: "crash", Severity: 1}}})
	first, _ := a.ClaimPendingAlerts(ctx, 100, time.Minute)
	if len(first) != 1 {
		t.Fatalf("first claim: %d", len(first))
	}
	if again, _ := b.ClaimPendingAlerts(ctx, 100, time.Minute); len(again) != 0 {
		t.Errorf("claimed during lease: %d", len(again))
	}
	time.Sleep(1100 * time.Millisecond)
	if again, _ := b.ClaimPendingAlerts(ctx, 100, time.Second); len(again) != 1 || again[0].ID != first[0].ID {
		t.Errorf("not reclaimed after lease expiry: %+v", again)
	}
}
