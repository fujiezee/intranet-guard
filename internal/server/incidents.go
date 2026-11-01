package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/store"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	status := model.IncidentStatus(r.URL.Query().Get("status"))
	list, err := s.store.ListIncidents(r.Context(), status)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type incidentDetail struct {
	Incident model.Incident       `json:"incident"`
	Alerts   []model.Alert        `json:"alerts"`
	Events   []model.HostEvent    `json:"events"` // 事件期间（前后各 30 分钟）该主机的审计记录
	Notes    []model.IncidentNote `json:"notes"`
	Stages   []alert.Stage        `json:"stages"`
	Agents   []string             `json:"agents"`
}

const timelineMargin = 30 * time.Minute

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ctx := r.Context()
	in, err := s.store.GetIncident(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	d := incidentDetail{Incident: in, Events: []model.HostEvent{}, Stages: alert.Stages}
	if d.Alerts, err = s.store.IncidentAlerts(ctx, id); err != nil {
		writeInternal(w, err)
		return
	}
	if d.Notes, err = s.store.IncidentNotes(ctx, id); err != nil {
		writeInternal(w, err)
		return
	}
	if d.Agents, err = s.store.AgentIDsForIP(ctx, in.IP); err != nil {
		writeInternal(w, err)
		return
	}
	for _, agentID := range d.Agents {
		ev, err := s.store.ListHostEvents(ctx, store.EventFilter{AgentID: agentID,
			From: in.FirstSeen.Add(-timelineMargin), To: in.LastSeen.Add(timelineMargin), Limit: 300})
		if err != nil {
			writeInternal(w, err)
			return
		}
		d.Events = append(d.Events, ev...)
	}
	sort.Slice(d.Events, func(i, j int) bool { return d.Events[i].Time.Before(d.Events[j].Time) })
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Status   model.IncidentStatus `json:"status"`
		Assignee *string              `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch req.Status {
	case "", model.IncidentOpen, model.IncidentInvestigating, model.IncidentResolved, model.IncidentFalsePositive:
	default:
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	if req.Assignee != nil && len(*req.Assignee) > 64 {
		writeError(w, http.StatusBadRequest, "assignee is too long")
		return
	}
	err = s.store.UpdateIncident(r.Context(), id, req.Status, req.Assignee, userFrom(r.Context()).Username)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "incident.update", strconv.FormatInt(id, 10), "status="+string(req.Status)+" assignee="+deref(req.Assignee), true)
	w.WriteHeader(http.StatusNoContent)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Server) addIncidentNote(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Body) == "" || len(req.Body) > 4000 {
		writeError(w, http.StatusBadRequest, "body is required (at most 4000 characters)")
		return
	}
	n, err := s.store.AddIncidentNote(r.Context(), id, userFrom(r.Context()).Username, strings.TrimSpace(req.Body))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) setAssetMeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Importance string   `json:"importance"`
		Owner      string   `json:"owner"`
		Tags       []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch req.Importance {
	case model.ImportanceNormal, model.ImportanceImportant, model.ImportanceCore:
	default:
		writeError(w, http.StatusBadRequest, "importance must be normal, important or core")
		return
	}
	var tags []string
	for _, t := range req.Tags {
		if t = strings.TrimSpace(strings.ReplaceAll(t, ",", " ")); t != "" && len(t) <= 32 {
			tags = append(tags, t)
		}
	}
	if len(req.Owner) > 64 || len(tags) > 20 {
		writeError(w, http.StatusBadRequest, "owner or tags too long")
		return
	}
	err := s.store.SetAssetMeta(r.Context(), r.PathValue("ip"), req.Importance, strings.TrimSpace(req.Owner), tags)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "asset.meta", r.PathValue("ip"), "importance="+req.Importance+" owner="+req.Owner, true)
	w.WriteHeader(http.StatusNoContent)
}
