package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"safe/internal/model"
	"safe/internal/store"
)

func (s *Server) listVulns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	vulns, err := s.store.ListVulns(r.Context(), store.VulnFilter{
		Status: model.VulnStatus(q.Get("status")), Severity: model.Severity(q.Get("severity")), IP: q.Get("ip"),
	})
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulns)
}

func (s *Server) setVulnStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Status model.VulnStatus `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Status != model.VulnIgnored && req.Status != model.VulnOpen {
		writeError(w, http.StatusBadRequest, "status must be ignored or open")
		return
	}
	err = s.store.SetVulnStatus(r.Context(), id, req.Status)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "vulnerability not found or not in a state that allows this change")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "vuln.status", strconv.FormatInt(id, 10), "status="+string(req.Status), true)
	w.WriteHeader(http.StatusNoContent)
}
