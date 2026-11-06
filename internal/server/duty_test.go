package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"safe/internal/duty"
	"safe/internal/model"
	"safe/internal/store"
)

// webhookSink 是一个通用 Webhook 接收端，记录收到的消息标题。
type webhookSink struct {
	mu     sync.Mutex
	titles []string
}

func newWebhookSink(t *testing.T) (*webhookSink, string) {
	sink := &webhookSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Title string `json:"title"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		sink.mu.Lock()
		sink.titles = append(sink.titles, body.Title)
		sink.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return sink, srv.URL
}

func (s *webhookSink) received(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.titles {
		if strings.HasPrefix(t, prefix) {
			n++
		}
	}
	return n
}

func TestDutyDesk(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	ctx := context.Background()
	queue := func() []store.DutyItem {
		t.Helper()
		var items []store.DutyItem
		call(t, ts, adminToken, "GET", "/api/v1/duty/queue", nil, &items)
		return items
	}
	metrics := func() store.DutyMetrics {
		t.Helper()
		var m store.DutyMetrics
		if code := call(t, ts, adminToken, "GET", "/api/v1/duty/metrics?range=today", nil, &m); code != http.StatusOK {
			t.Fatalf("metrics: %d", code)
		}
		return m
	}

	// 新资产告警（不属于事件）+ 暴力破解形成的事件
	runTask(t, ts, adminToken, true, []int{22}, asset("10.0.0.1", 22))
	runTask(t, ts, adminToken, false, []int{22, 6379}, asset("10.0.0.1", 22, 6379), asset("10.0.0.2", 22))
	var fails []model.HostEvent
	for i := 0; i < 10; i++ {
		fails = append(fails, model.HostEvent{Type: model.EventLoginFailed, Time: time.Now(), User: "root", SrcIP: "10.9.9.9"})
	}
	call(t, ts, agentToken, "POST", "/api/v1/agent/report", model.AgentReport{
		Agent: model.AgentInfo{ID: "web01", Hostname: "web01", IPs: []string{"10.0.0.21"}}, Events: fails}, nil)

	items := queue()
	var alertItem, incidentItem *store.DutyItem
	for i := range items {
		it := &items[i]
		if it.ResponseDue == nil {
			t.Errorf("item without response due: %+v", it)
		}
		switch {
		case it.Kind == "incident" && incidentItem == nil:
			incidentItem = it
		case it.Kind == "alert" && alertItem == nil:
			alertItem = it
		}
	}
	if alertItem == nil || incidentItem == nil {
		t.Fatalf("queue needs both an alert and an incident: %+v", items)
	}
	for i := 1; i < len(items); i++ {
		if r := map[model.Severity]int{"low": 0, "medium": 1, "high": 2}; r[items[i].Severity] > r[items[i-1].Severity] {
			t.Fatalf("queue not ordered by severity: %+v", items)
		}
	}
	if incidentItem.ResolveDue == nil {
		t.Errorf("incident without resolve due: %+v", incidentItem)
	}

	// 确认告警、认领并结案事件
	call(t, ts, adminToken, "POST", fmt.Sprintf("/api/v1/alerts/%d/ack", alertItem.ID), nil, nil)
	call(t, ts, adminToken, "PATCH", fmt.Sprintf("/api/v1/incidents/%d", incidentItem.ID), map[string]any{"assignee": "admin"}, nil)
	in, _ := st.GetIncident(ctx, incidentItem.ID)
	if in.AckedAt == nil || in.ResolvedAt != nil {
		t.Fatalf("claim should set acked_at only: %+v", in)
	}
	call(t, ts, adminToken, "PATCH", fmt.Sprintf("/api/v1/incidents/%d", incidentItem.ID), map[string]any{"status": "resolved"}, nil)
	for _, it := range queue() {
		if it.Kind == incidentItem.Kind && it.ID == incidentItem.ID || it.Kind == "alert" && it.ID == alertItem.ID {
			t.Fatalf("handled item still queued: %+v", it)
		}
	}
	m := metrics()
	if m.Incidents != 1 || m.Resolved != 1 || m.MTTRSamples != 1 || m.MTTASamples != 2 || m.Handled < 2 {
		t.Fatalf("metrics after handling: %+v", m)
	}
	if m.SLATotal != 3 || m.SLAMet != 3 {
		t.Fatalf("handled within SLA: total=%d met=%d", m.SLATotal, m.SLAMet)
	}
	// 一天之后再看：没人处理的告警全部超时
	later, err := st.DutyMetrics(ctx, m.From, m.To, time.Now().Add(25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if later.SLATotal <= m.SLATotal || later.SLAMet != m.SLAMet {
		t.Fatalf("unhandled alerts should count as breaches later: %+v", later)
	}
	// 重新打开事件：清空结案时间，保留认领时间
	call(t, ts, adminToken, "PATCH", fmt.Sprintf("/api/v1/incidents/%d", incidentItem.ID), map[string]any{"status": "investigating"}, nil)
	if in, _ := st.GetIncident(ctx, incidentItem.ID); in.ResolvedAt != nil || in.AckedAt == nil {
		t.Fatalf("reopen: %+v", in)
	}

	// SLA 设置
	if code := call(t, ts, adminToken, "PUT", "/api/v1/duty/sla", map[string]any{"response": map[string]int{"high": -1}}, nil); code != http.StatusBadRequest {
		t.Errorf("negative SLA: %d", code)
	}
	sla := store.SLA{Response: map[model.Severity]int{"high": 30, "medium": 240, "low": 0}, Resolve: map[model.Severity]int{"high": 480}}
	if code := call(t, ts, adminToken, "PUT", "/api/v1/duty/sla", sla, nil); code != http.StatusNoContent {
		t.Fatalf("set SLA: %d", code)
	}
	var got store.SLA
	call(t, ts, adminToken, "GET", "/api/v1/duty/sla", nil, &got)
	if got.Response["high"] != 30 || got.Resolve["medium"] != 0 {
		t.Fatalf("SLA round trip: %+v", got)
	}
	for _, it := range queue() {
		if it.Severity == model.SeverityLow && it.ResponseDue != nil {
			t.Fatalf("low items are not timed after setting 0: %+v", it)
		}
	}

	// 交接班：汇总遗留事项并推送到启用的渠道
	sink, url := newWebhookSink(t)
	call(t, ts, adminToken, "POST", "/api/v1/notify-channels",
		model.NotifyChannel{Name: "值守群", Type: model.ChannelWebhook, URL: url, MinSeverity: model.SeverityHigh}, nil)
	var h store.Handover
	if code := call(t, ts, adminToken, "POST", "/api/v1/duty/handovers", map[string]string{"note": "10.0.0.21 待运维确认"}, &h); code != http.StatusCreated {
		t.Fatalf("handover: %d", code)
	}
	if h.Summary.OpenTotal != len(queue()) || h.Note != "10.0.0.21 待运维确认" || h.Author != "admin" {
		t.Fatalf("handover summary: %+v", h)
	}
	var preview store.Handover
	call(t, ts, adminToken, "GET", "/api/v1/duty/handovers/preview", nil, &preview)
	if !preview.From.Equal(h.To) {
		t.Fatalf("next shift should start at the last handover: %v vs %v", preview.From, h.To)
	}
	var list []store.Handover
	call(t, ts, adminToken, "GET", "/api/v1/duty/handovers", nil, &list)
	if len(list) != 1 || list[0].Summary.OpenTotal != h.Summary.OpenTotal {
		t.Fatalf("handover list: %+v", list)
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.received("【内网防护】交接班") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if sink.received("【内网防护】交接班") != 1 {
		t.Fatalf("handover push: %v", sink.titles)
	}
	if code := call(t, ts, viewerToken(t, ts, adminToken), "POST", "/api/v1/duty/handovers", map[string]string{}, nil); code != http.StatusForbidden {
		t.Errorf("viewer handover: %d", code)
	}
}

func TestReports(t *testing.T) {
	ts, adminToken, st := newTestServerWithStore(t)
	ctx := context.Background()
	daily, url := newWebhookSink(t)
	weekly, url2 := newWebhookSink(t)
	var chDaily, chWeekly model.NotifyChannel
	call(t, ts, adminToken, "POST", "/api/v1/notify-channels", model.NotifyChannel{Name: "值守群", Type: model.ChannelWebhook, URL: url, MinSeverity: model.SeverityHigh}, &chDaily)
	call(t, ts, adminToken, "POST", "/api/v1/notify-channels", model.NotifyChannel{Name: "领导群", Type: model.ChannelWebhook, URL: url2, MinSeverity: model.SeverityHigh}, &chWeekly)
	call(t, ts, adminToken, "PUT", fmt.Sprintf("/api/v1/notify-channels/%d/reports", chDaily.ID), map[string]bool{"daily_report": true}, nil)
	call(t, ts, adminToken, "PUT", fmt.Sprintf("/api/v1/notify-channels/%d/reports", chWeekly.ID), map[string]bool{"weekly_report": true}, nil)
	var chans []model.NotifyChannel
	call(t, ts, adminToken, "GET", "/api/v1/notify-channels", nil, &chans)
	if !chans[0].DailyReport || chans[0].WeeklyReport || !chans[1].WeeklyReport {
		t.Fatalf("report flags: %+v", chans)
	}

	loc := time.FixedZone("CST", 8*3600)
	monday := time.Date(2026, 11, 9, 9, 30, 0, 0, loc) // 周一 9:30：日报和周报都到了时间
	hc := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 2; i++ { // 第二次不重复生成、不重复推送
		if err := duty.RunOnce(ctx, st, hc, monday, loc); err != nil {
			t.Fatal(err)
		}
	}
	if daily.received("【内网防护】日报 11-08") != 1 || daily.received("【内网防护】周报") != 0 {
		t.Fatalf("daily channel: %v", daily.titles)
	}
	if weekly.received("【内网防护】周报 11-02 – 11-08") != 1 || weekly.received("【内网防护】日报") != 0 {
		t.Fatalf("weekly channel: %v", weekly.titles)
	}

	// 停机很久后补生成的报表只保存不推送
	if err := duty.RunOnce(ctx, st, hc, monday.Add(24*time.Hour+8*time.Hour), loc); err != nil {
		t.Fatal(err)
	}
	if daily.received("【内网防护】日报 11-09") != 0 {
		t.Fatalf("stale daily report pushed: %v", daily.titles)
	}

	var reports []struct {
		store.Report
		Title string `json:"title"`
	}
	call(t, ts, adminToken, "GET", "/api/v1/reports", nil, &reports)
	if len(reports) != 3 {
		t.Fatalf("reports: %+v", reports)
	}
	call(t, ts, adminToken, "GET", "/api/v1/reports?kind=weekly", nil, &reports)
	if len(reports) != 1 || reports[0].Kind != store.ReportWeekly || reports[0].Data != nil {
		t.Fatalf("weekly list: %+v", reports)
	}
	var detail struct {
		store.Report
		Text string `json:"text"`
	}
	call(t, ts, viewerToken(t, ts, adminToken), "GET", fmt.Sprintf("/api/v1/reports/%d", reports[0].ID), nil, &detail)
	if detail.Data == nil || !strings.Contains(detail.Text, "**值守**") {
		t.Fatalf("report detail: %+v", detail)
	}
}

func TestReportPeriod(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, loc) } // 11-09 是周一
	day := func(t time.Time) string { return t.In(loc).Format("01-02 15") }
	for _, c := range []struct {
		kind            string
		now             time.Time
		sched, from, to string
	}{
		{store.ReportDaily, at(6, 10), "11-06 09", "11-05 00", "11-06 00"},
		{store.ReportDaily, at(6, 8), "11-05 09", "11-04 00", "11-05 00"},
		{store.ReportWeekly, at(9, 9), "11-09 09", "11-02 00", "11-09 00"},
		{store.ReportWeekly, at(9, 8), "11-02 09", "10-26 00", "11-02 00"},
		{store.ReportWeekly, at(8, 23), "11-02 09", "10-26 00", "11-02 00"},
	} {
		sched, from, to := duty.Period(c.kind, c.now, loc)
		if day(sched) != c.sched || day(from) != c.from || day(to) != c.to {
			t.Errorf("%s at %s: got %s / %s – %s", c.kind, day(c.now), day(sched), day(from), day(to))
		}
	}
}

// viewerToken 创建只读用户并返回其登录令牌。
func viewerToken(t *testing.T, ts *httptest.Server, adminToken string) string {
	t.Helper()
	var u model.User
	call(t, ts, adminToken, "POST", "/api/v1/users", map[string]string{"username": "reader", "password": "reader-password", "role": "viewer"}, &u)
	return login(t, ts, "reader", "reader-password")
}
