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

	// office 有存量 IDS 事件：先于注册写入，相当于升级前的数据，ids_seen 要靠回填得知。
	// lab 之后才上报 IDS，noeve 从未上报，gone 已吊销。
	if err := st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "office", Events: []model.IDSEvent{{
		Time: t0, SrcIP: "192.168.1.5", DestIP: "223.5.5.5", Proto: "UDP", SignatureID: 1, Signature: "info", Severity: 3}}}); err != nil {
		t.Fatal(err)
	}
	enrollProbes(t, st, "office", "lab", "noeve", "gone")
	for _, id := range []string{"office", "lab", "noeve", "gone"} {
		if err := st.TouchProbe(ctx, id, t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RevokeNode(ctx, model.NodeProbe, "gone"); err != nil {
		t.Fatal(err)
	}

	// 10 分钟：都未超时
	check(t0.Add(10*time.Minute), 0)

	// 20 分钟：office、lab、noeve 继续通信；office 的 IDS（回填为 t0）超时，lab、noeve 没有 IDS 记录不检查；
	// gone 已吊销，不告警离线。
	for _, id := range []string{"office", "lab", "noeve"} {
		st.TouchProbe(ctx, id, t0.Add(19*time.Minute))
	}
	check(t0.Add(20*time.Minute), 1)
	check(t0.Add(21*time.Minute), 0) // 同一状态只告警一次
	if open, _ := probeAlerts(t, st); open[model.AlertIDSSilent] != 1 || open[model.AlertProbeOffline] != 0 {
		t.Fatalf("after IDS stop: %v", open)
	}

	// lab 开始上报 IDS，之后 noeve 和 lab 都停止通信
	if err := st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "lab", Events: []model.IDSEvent{{
		Time: time.Now(), SrcIP: "192.168.1.6", DestIP: "223.5.5.5", Proto: "UDP", SignatureID: 1, Signature: "info", Severity: 3}}}); err != nil {
		t.Fatal(err)
	}
	st.TouchProbe(ctx, "office", t0.Add(40*time.Minute))
	check(t0.Add(40*time.Minute), 2) // lab、noeve 离线（最后通信 19 分钟）
	if open, _ := probeAlerts(t, st); open[model.AlertProbeOffline] != 2 {
		t.Fatalf("after probes stop: %v", open)
	}

	// office 恢复 IDS 上报：流量检测中断告警由 system 自动确认
	if err := st.SaveIDSReport(ctx, model.IDSReport{ProbeID: "office", Events: []model.IDSEvent{{
		Time: time.Now(), SrcIP: "192.168.1.5", DestIP: "223.5.5.5", Proto: "UDP", SignatureID: 1, Signature: "info", Severity: 3}}}); err != nil {
		t.Fatal(err)
	}
	// noeve 恢复通信：离线告警自动确认
	st.TouchProbe(ctx, "office", time.Now())
	st.TouchProbe(ctx, "noeve", time.Now())
	check(time.Now(), 2)
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
	check(time.Now().Add(20*time.Minute), 2)
	if open, _ := probeAlerts(t, st); open[model.AlertProbeOffline] != 3 || open[model.AlertIDSSilent] != 0 {
		t.Fatalf("second outage: %v", open)
	}
}
