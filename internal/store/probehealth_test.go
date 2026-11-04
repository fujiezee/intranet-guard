package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"safe/internal/model"
	"safe/internal/store"
	"safe/internal/store/storetest"
)

func enrollProbes(t *testing.T, st *store.Store, ids ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateEnrollToken(ctx, model.EnrollToken{Kind: model.NodeProbe, MaxUses: len(ids),
		ExpiresAt: time.Now().Add(time.Hour), CreatedBy: "test"}, "probe-hash"); err != nil {
		t.Fatal(err)
	}
	sign := func() (string, time.Time, error) {
		return fmt.Sprint(time.Now().UnixNano()), time.Now().Add(time.Hour), nil
	}
	for _, id := range ids {
		if _, err := st.Enroll(ctx, "probe-hash", model.NodeProbe, id, sign); err != nil {
			t.Fatal(err)
		}
	}
}

// probeAlerts 返回各类型未确认的告警数，以及全部告警（用于检查自动确认）。
func probeAlerts(t *testing.T, st *store.Store) (open map[model.AlertType]int, all []model.Alert) {
	t.Helper()
	all, err := st.ListAlerts(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	open = map[model.AlertType]int{}
	for _, a := range all {
		if a.Status == model.AlertOpen {
			open[a.Type]++
		}
	}
	return open, all
}

func TestProbeHealth(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	after := 15 * time.Minute
	check := func(now time.Time, want int) {
		t.Helper()
		if n, err := st.CheckProbeHealth(ctx, now, after); err != nil || n != want {
			t.Fatalf("CheckProbeHealth at %s = %d, %v; want %d", now.Sub(t0), n, err, want)
		}
	}
	// office、lab 带 -eve；noeve 不上报 eve 状态（旧版探针或未接 Suricata）；gone 已吊销。
	enrollProbes(t, st, "office", "lab", "noeve", "gone")
	for _, id := range []string{"office", "lab", "noeve", "gone"} {
		if err := st.TouchProbe(ctx, id, t0); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"office", "lab"} {
		if err := st.ReportEve(ctx, id, t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RevokeNode(ctx, model.NodeProbe, "gone"); err != nil {
		t.Fatal(err)
	}
	check(t0.Add(10*time.Minute), 0)

	// 20 分钟：三个探针都在通信。网络安静、没有任何 IDS 告警，但 lab 的 eve.json 仍在增长，不告警；
	// office 的 eve.json 停止增长，告警；noeve 不检查；gone 已吊销，不告警离线。
	for _, id := range []string{"office", "lab", "noeve"} {
		st.TouchProbe(ctx, id, t0.Add(19*time.Minute))
	}
	st.ReportEve(ctx, "lab", t0.Add(19*time.Minute))
	check(t0.Add(20*time.Minute), 1)
	check(t0.Add(21*time.Minute), 0) // 同一状态只告警一次
	if open, _ := probeAlerts(t, st); open[model.AlertIDSSilent] != 1 || open[model.AlertProbeOffline] != 0 {
		t.Fatalf("after eve stops: %v", open)
	}

	// 40 分钟：lab、noeve 停止通信，离线（最后通信 19 分钟）
	st.TouchProbe(ctx, "office", t0.Add(40*time.Minute))
	check(t0.Add(40*time.Minute), 2)
	if open, _ := probeAlerts(t, st); open[model.AlertProbeOffline] != 2 {
		t.Fatalf("after probes stop: %v", open)
	}

	// office 的 eve.json 恢复增长、noeve 恢复通信：两条告警由 system 自动确认
	now := time.Now()
	st.TouchProbe(ctx, "office", now)
	st.ReportEve(ctx, "office", now)
	st.TouchProbe(ctx, "noeve", now)
	check(now, 2)
	open, all := probeAlerts(t, st)
	if open[model.AlertIDSSilent] != 0 || open[model.AlertProbeOffline] != 1 {
		t.Fatalf("after recovery: %v", open)
	}
	resolved := 0
	for _, a := range all {
		if a.Status == model.AlertAcked {
			if a.AckedBy != "system" || a.ResolutionNote == "" {
				t.Errorf("auto-acked alert %d: by %q note %q", a.ID, a.AckedBy, a.ResolutionNote)
			}
			resolved++
		}
	}
	if resolved != 2 {
		t.Errorf("auto-acked alerts = %d, want 2", resolved)
	}

	// 再次离线会重新告警，不被 30 分钟的去重窗口吞掉：office、noeve 离线，lab 仍是上一次的告警
	check(now.Add(20*time.Minute), 2)
	if open, _ := probeAlerts(t, st); open[model.AlertProbeOffline] != 3 || open[model.AlertIDSSilent] != 0 {
		t.Fatalf("second outage: %v", open)
	}
}
