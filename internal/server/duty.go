package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"safe/internal/duty"
	"safe/internal/model"
	"safe/internal/store"
)

// 值守工作台和报表。时间按管理中心所在时区计算（"今日"、报表周期）。

func (s *Server) dutyQueue(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.DutyQueue(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// dutyMetrics 统计 range 指定的时段：today（今日 0 点起）、7d、30d。
func (s *Server) dutyMetrics(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	var from time.Time
	switch r.URL.Query().Get("range") {
	case "", "today":
		y, m, d := now.Date()
		from = time.Date(y, m, d, 0, 0, 0, 0, time.Local)
	case "7d":
		from = now.AddDate(0, 0, -7)
	case "30d":
		from = now.AddDate(0, 0, -30)
	default:
		writeError(w, http.StatusBadRequest, "range must be today, 7d or 30d")
		return
	}
	m, err := s.store.DutyMetrics(r.Context(), from, now, now)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) getSLA(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetSLA(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

const maxSLAMinutes = 30 * 24 * 60

func (s *Server) setSLA(w http.ResponseWriter, r *http.Request) {
	var c store.SLA
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	for _, limits := range []map[model.Severity]int{c.Response, c.Resolve} {
		for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
			if v := limits[sev]; v < 0 || v > maxSLAMinutes {
				writeError(w, http.StatusBadRequest, "SLA limits must be 0-43200 minutes")
				return
			}
		}
		for sev := range limits {
			if sev != model.SeverityHigh && sev != model.SeverityMedium && sev != model.SeverityLow {
				writeError(w, http.StatusBadRequest, "unknown severity")
				return
			}
		}
	}
	if err := s.store.SetSLA(r.Context(), c); err != nil {
		writeInternal(w, err)
		return
	}
	raw, _ := json.Marshal(c)
	s.audit(r, "", "duty.sla", "", string(raw), true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listHandovers(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListHandovers(r.Context(), 30)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) previewHandover(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.PreviewHandover(r.Context(), time.Now())
	if err != nil {
		writeInternal(w, err)
		return
	}
	h.Author = userFrom(r.Context()).Username
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) createHandover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	note := strings.TrimSpace(req.Note)
	if len([]rune(note)) > 2000 {
		writeError(w, http.StatusBadRequest, "note is too long (at most 2000 characters)")
		return
	}
	h, err := s.store.CreateHandover(r.Context(), userFrom(r.Context()).Username, note, time.Now())
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "duty.handover", strconv.FormatInt(h.ID, 10), fmt.Sprintf("open=%d overdue=%d", h.Summary.OpenTotal, h.Summary.OpenOverdue), true)
	go duty.PushHandover(context.WithoutCancel(r.Context()), s.store, h, time.Local)
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != store.ReportDaily && kind != store.ReportWeekly {
		writeError(w, http.StatusBadRequest, "kind must be daily or weekly")
		return
	}
	list, err := s.store.ListReports(r.Context(), kind, 120)
	if err != nil {
		writeInternal(w, err)
		return
	}
	type item struct {
		store.Report
		Title string `json:"title"`
	}
	out := make([]item, len(list))
	for i, rep := range list {
		out[i] = item{rep, duty.ReportTitle(rep, time.Local)}
	}
	writeJSON(w, http.StatusOK, out)
}

// getReport 返回报表内容，以及与推送内容相同的 Markdown 文本（用于导出）。
func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rep, err := s.store.GetReport(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "report not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	_, text := duty.FormatReport(rep, time.Local)
	writeJSON(w, http.StatusOK, struct {
		store.Report
		Title string `json:"title"`
		Text  string `json:"text"`
	}{rep, duty.ReportTitle(rep, time.Local), text})
}

func (s *Server) setChannelReports(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Daily  bool `json:"daily_report"`
		Weekly bool `json:"weekly_report"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.SetChannelReports(r.Context(), id, req.Daily, req.Weekly); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "channel not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "notify_channel.reports", strconv.FormatInt(id, 10),
		fmt.Sprintf("daily=%v weekly=%v", req.Daily, req.Weekly), true)
	w.WriteHeader(http.StatusNoContent)
}
