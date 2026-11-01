package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"safe/internal/model"
	"safe/internal/store"
)

type createActionRequest struct {
	AgentID string            `json:"agent_id"`
	Type    string            `json:"type"`
	Params  map[string]string `json:"params"`
	Reason  string            `json:"reason"`
}

// validateAction 校验并规范化处置参数。只允许发起主动作；撤销动作通过 rollback 接口产生。
func validateAction(req *createActionRequest) error {
	if req.Params == nil {
		req.Params = map[string]string{}
	}
	p := req.Params
	clean := map[string]string{}
	switch req.Type {
	case model.ActBlockIP:
		ip, err := netip.ParseAddr(strings.TrimSpace(p["ip"]))
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("ip must be a unicast, non-loopback address")
		}
		clean["ip"] = ip.Unmap().String()
		secs := 86400
		if v := p["duration"]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 60 || n > 30*86400 {
				return errors.New("duration must be 60-2592000 seconds")
			}
			secs = n
		}
		clean["duration"] = strconv.Itoa(secs)
	case model.ActKillProcess:
		pid, err := strconv.Atoi(p["pid"])
		if err != nil || pid <= 1 {
			return errors.New("pid must be greater than 1")
		}
		if !filepath.IsAbs(p["exe"]) {
			return errors.New("exe (absolute path of the process executable) is required")
		}
		clean["pid"], clean["exe"] = strconv.Itoa(pid), p["exe"]
	case model.ActQuarantine:
		if !filepath.IsAbs(p["path"]) || filepath.Clean(p["path"]) != p["path"] {
			return errors.New("path must be a clean absolute path")
		}
		clean["path"] = p["path"]
	case model.ActIsolate:
		var allow []string
		for _, s := range strings.Split(p["allow"], ",") {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("invalid allow address %q", s)
			}
			allow = append(allow, s)
		}
		clean["allow"] = strings.Join(allow, ",")
	default:
		return errors.New("type must be block_ip, kill_process, quarantine_file or isolate_host")
	}
	req.Params = clean
	if strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 {
		return errors.New("reason is required (at most 500 characters)")
	}
	return nil
}

func (s *Server) createAction(w http.ResponseWriter, r *http.Request) {
	var req createActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validNodeID.MatchString(req.AgentID) {
		writeError(w, http.StatusBadRequest, "invalid agent_id")
		return
	}
	if err := validateAction(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, err := s.store.CreateAction(r.Context(), model.ResponseAction{AgentID: req.AgentID, Type: req.Type, Params: req.Params,
		Reason: strings.TrimSpace(req.Reason), CreatedBy: userFrom(r.Context()).Username})
	if err != nil {
		writeInternal(w, err)
		return
	}
	params, _ := json.Marshal(a.Params)
	s.audit(r, "", "action.create", a.ID, fmt.Sprintf("agent=%s type=%s params=%s reason=%s", a.AgentID, a.Type, params, a.Reason), true)
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) approveAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.ApproveAction(r.Context(), id, userFrom(r.Context()).Username)
	switch {
	case errors.Is(err, store.ErrSelfApproval):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "action not found or not awaiting approval")
		return
	case err != nil:
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "action.approve", id, "", true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rollbackAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "撤销"
	}
	undo, err := s.store.Rollback(r.Context(), r.PathValue("id"), userFrom(r.Context()).Username, strings.TrimSpace(req.Reason))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "action not found")
		return
	case errors.Is(err, store.ErrNotRollbackable):
		writeError(w, http.StatusBadRequest, "only completed block / quarantine / isolate actions can be rolled back, once")
		return
	case err != nil:
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "action.rollback", r.PathValue("id"), "undo="+undo.ID, true)
	writeJSON(w, http.StatusCreated, undo)
}

func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListActions(r.Context(), 500)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
