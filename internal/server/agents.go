package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"safe/internal/model"
	"safe/internal/store"
)

func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	var rep model.AgentReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var ok bool
	if rep.Agent.ID, ok = nodeIdentity(w, r, rep.Agent.ID); !ok {
		return
	}
	err := s.store.SaveAgentReport(r.Context(), rep)
	if errors.Is(err, store.ErrTooManyEvents) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	if len(rep.Events) > 0 {
		slog.Info("agent events saved", "agent", rep.Agent.ID, "events", len(rep.Events))
	}
	if err := s.store.RecordCommandResults(r.Context(), rep.Agent.ID, rep.Results); err != nil {
		writeInternal(w, err)
		return
	}
	cmds, err := s.store.ClaimSimulations(r.Context(), rep.Agent.ID)
	if err != nil {
		writeInternal(w, err)
		return
	}
	actions, err := s.store.ClaimActions(r.Context(), rep.Agent.ID)
	if err != nil {
		writeInternal(w, err)
		return
	}
	cmds = append(cmds, actions...)
	writeJSON(w, http.StatusOK, model.AgentReportResponse{Commands: cmds})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) listHostEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{AgentID: q.Get("agent_id"), Type: model.HostEventType(q.Get("type")), SrcIP: q.Get("src_ip"), Limit: 500}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "limit must be within 1-5000")
			return
		}
		f.Limit = n
	}
	events, err := s.store.ListHostEvents(r.Context(), f)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}
