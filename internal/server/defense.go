package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"safe/internal/alert"
	"safe/internal/honeypot"
	"safe/internal/model"
	"safe/internal/netintel"
	"safe/internal/simulate"
	"safe/internal/store"
)

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": alert.Catalog, "scenarios": simulate.Scenarios})
}

// --- 蜜罐 ---

func (s *Server) listHoneypots(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListHoneypots(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) setHoneypot(w http.ResponseWriter, r *http.Request) {
	probeID := r.PathValue("probe")
	if !validNodeID.MatchString(probeID) {
		writeError(w, http.StatusBadRequest, "invalid probe id")
		return
	}
	var cfg model.HoneypotConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(cfg.Services) > 32 {
		writeError(w, http.StatusBadRequest, "at most 32 services")
		return
	}
	ports := map[int]bool{}
	for _, svc := range cfg.Services {
		if !honeypot.Types[svc.Type] {
			writeError(w, http.StatusBadRequest, "unknown service type "+svc.Type)
			return
		}
		if svc.Port < 1 || svc.Port > 65535 || ports[svc.Port] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid or duplicate port %d", svc.Port))
			return
		}
		ports[svc.Port] = true
	}
	if cfg.IgnoreSources == nil {
		cfg.IgnoreSources = []string{}
	}
	for i, src := range cfg.IgnoreSources {
		src = strings.TrimSpace(src)
		if _, err := netip.ParsePrefix(src); err != nil {
			if _, err := netip.ParseAddr(src); err != nil {
				writeError(w, http.StatusBadRequest, "invalid ignore source "+src)
				return
			}
		}
		cfg.IgnoreSources[i] = src
	}
	if err := s.store.SetHoneypot(r.Context(), probeID, cfg); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "honeypot.set", probeID, fmt.Sprintf("enabled=%v services=%d", cfg.Enabled, len(cfg.Services)), true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listHoneypotEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListHoneypotEvents(r.Context(), 500)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

type probeConfigRequest struct {
	IPs    []string       `json:"ips"`
	Status map[int]string `json:"status"`
}

type probeConfigResponse struct {
	Honeypot     model.HoneypotConfig `json:"honeypot"`
	IntelVersion int64                `json:"intel_version"` // 变化时探针重新拉取 /api/v1/probe/intel
	Net          netintel.Config      `json:"net"`
}

func (s *Server) probeConfig(w http.ResponseWriter, r *http.Request) {
	var req probeConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	probeID, ok := nodeIdentity(w, r, r.URL.Query().Get("probe_id"))
	if !ok {
		return
	}
	cfg, err := s.store.ProbeConfig(r.Context(), probeID, req.IPs, req.Status)
	if err != nil {
		writeInternal(w, err)
		return
	}
	resp := probeConfigResponse{Honeypot: cfg}
	if resp.IntelVersion, err = s.store.IntelVersion(r.Context()); err != nil {
		writeInternal(w, err)
		return
	}
	if resp.Net, err = s.store.NetConfig(r.Context()); err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type honeypotReport struct {
	ProbeID string                `json:"probe_id"`
	Events  []model.HoneypotEvent `json:"events"`
}

func (s *Server) submitHoneypotEvents(w http.ResponseWriter, r *http.Request) {
	var rep honeypotReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	probeID, ok := nodeIdentity(w, r, rep.ProbeID)
	if !ok {
		return
	}
	err := s.store.SaveHoneypotEvents(r.Context(), probeID, rep.Events)
	if errors.Is(err, store.ErrTooManyEvents) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- 攻击模拟自检 ---

type createSimulationsRequest struct {
	AgentID   string   `json:"agent_id"`
	Scenarios []string `json:"scenarios"`
}

func (s *Server) createSimulations(w http.ResponseWriter, r *http.Request) {
	var req createSimulationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validNodeID.MatchString(req.AgentID) || len(req.Scenarios) == 0 {
		writeError(w, http.StatusBadRequest, "agent_id and scenarios are required")
		return
	}
	// 先全部校验（包括为蜜罐场景选目标），任何一项不满足都不创建，避免只创建了一部分
	target := ""
	for _, sc := range req.Scenarios {
		if _, ok := simulate.Get(sc); !ok {
			writeError(w, http.StatusBadRequest, "unknown scenario "+sc)
			return
		}
		if sc == simulate.HoneypotAccess && target == "" {
			var err error
			if target, err = s.honeypotTarget(r); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	created := []model.Simulation{}
	for _, sc := range req.Scenarios {
		params := map[string]string{}
		if sc == simulate.HoneypotAccess {
			params["target"] = target
		}
		sim, err := s.store.CreateSimulation(r.Context(), req.AgentID, sc, params, userFrom(r.Context()).Username)
		if err != nil {
			writeInternal(w, err)
			return
		}
		created = append(created, sim)
	}
	s.audit(r, "", "simulation.create", req.AgentID, strings.Join(req.Scenarios, ","), true)
	writeJSON(w, http.StatusCreated, created)
}

// honeypotTarget 选一个正在监听的蜜罐端口作为"访问蜜罐"场景的目标。
func (s *Server) honeypotTarget(r *http.Request) (string, error) {
	list, err := s.store.ListHoneypots(r.Context())
	if err != nil {
		return "", err
	}
	for _, h := range list {
		if !h.Config.Enabled || len(h.ProbeIPs) == 0 {
			continue
		}
		var ip string
		for _, cand := range h.ProbeIPs {
			if a, err := netip.ParseAddr(cand); err == nil && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a.Is4() {
				ip = cand
				break
			}
		}
		for port, st := range h.Status {
			if st == "listening" && ip != "" {
				return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port)).String(), nil
			}
		}
	}
	return "", errors.New("no running honeypot: enable a honeypot on a probe first")
}

func (s *Server) listSimulations(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	sims, err := s.store.ListSimulations(r.Context(), limit)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sims)
}
