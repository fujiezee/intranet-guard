package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"safe/internal/alert"
	"safe/internal/model"
	"safe/internal/scanner"
	"safe/internal/store"
)

// 安全验证只能针对授权范围内的资产：管理员先登记范围，创建和开始时都检查，范围外的目标直接拒绝。
const minScopeBits = 8 // 比 /8 更大的范围几乎一定是填错了

func parseScope(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if ip, err := netip.ParseAddr(s); err == nil {
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, errors.New("cidr must be an IP address or network")
	}
	if p.Bits() < minScopeBits {
		return p, errors.New("scope is too large (at most /8)")
	}
	return p.Masked(), nil
}

// outOfScope 返回不在授权范围内的第一个地址，都在范围内时返回空。
func (s *Server) outOfScope(ctx context.Context, targets []string) (string, error) {
	addrs, err := scanner.ExpandTargets(targets)
	if err != nil {
		return "", err
	}
	scopes, err := s.store.ListValidationScopes(ctx)
	if err != nil {
		return "", err
	}
	prefixes := make([]netip.Prefix, 0, len(scopes))
	for _, v := range scopes {
		if p, err := netip.ParsePrefix(v.CIDR); err == nil {
			prefixes = append(prefixes, p)
		}
	}
next:
	for _, a := range addrs {
		a = a.Unmap()
		for _, p := range prefixes {
			if p.Contains(a) {
				continue next
			}
		}
		return a.String(), nil
	}
	return "", nil
}

func (s *Server) listValidationScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := s.store.ListValidationScopes(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (s *Server) addValidationScope(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.Note == "" || len(req.Note) > 200 {
		writeError(w, http.StatusBadRequest, "note is required (at most 200 characters)")
		return
	}
	p, err := parseScope(req.CIDR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := s.store.AddValidationScope(r.Context(), model.ValidationScope{CIDR: p.String(), Note: req.Note, CreatedBy: userFrom(r.Context()).Username})
	if errors.Is(err, store.ErrScopeExists) {
		writeError(w, http.StatusConflict, err.Error())
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "validation.scope.add", v.CIDR, v.Note, true)
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) deleteValidationScope(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scope id")
		return
	}
	switch err := s.store.DeleteValidationScope(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "scope not found")
	case err != nil:
		writeInternal(w, err)
	default:
		s.audit(r, "", "validation.scope.delete", r.PathValue("id"), "", true)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) listValidationRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListValidationRuns(r.Context(), 200)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

type createValidationRequest struct {
	Name         string   `json:"name"`
	ProbeID      string   `json:"probe_id"`
	Targets      []string `json:"targets"`
	Ports        []int    `json:"ports"`
	WeakPassword bool     `json:"weak_password"`
	Nuclei       bool     `json:"nuclei"`
}

func (s *Server) createValidationRun(w http.ResponseWriter, r *http.Request) {
	var req createValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "name is required (at most 100 characters)")
		return
	}
	if req.ProbeID == "" || len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "probe_id and targets are required")
		return
	}
	if len(req.Ports) == 0 {
		req.Ports = scanner.DefaultPorts
	}
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			writeError(w, http.StatusBadRequest, "ports must be within 1-65535")
			return
		}
	}
	u := userFrom(r.Context()).Username
	if !s.checkScope(w, r, req.Targets, "validation.create") {
		return
	}
	run, err := s.store.CreateValidationRun(r.Context(), model.ValidationRun{Name: req.Name, ProbeID: req.ProbeID, Targets: req.Targets,
		Ports: req.Ports, WeakPassword: req.WeakPassword, Nuclei: req.Nuclei, CreatedBy: u})
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "validation.create", run.ID, fmt.Sprintf("probe=%s weak_password=%v nuclei=%v targets=%v", run.ProbeID, run.WeakPassword, run.Nuclei, run.Targets), true)
	if !run.WeakPassword && !run.Nuclei { // 低风险：发起的管理员就是批准人
		if err := s.store.StartValidationRun(r.Context(), run.ID, u, newID()); err != nil {
			writeInternal(w, err)
			return
		}
		s.audit(r, "", "validation.start", run.ID, "", true)
		run.Status, run.ApprovedBy = model.ValRunning, u
	}
	writeJSON(w, http.StatusCreated, run)
}

// checkScope 检查目标是否都在授权范围内，范围外的尝试写入审计。
func (s *Server) checkScope(w http.ResponseWriter, r *http.Request, targets []string, action string) bool {
	if _, err := scanner.ExpandTargets(targets); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	addr, err := s.outOfScope(r.Context(), targets)
	if err != nil {
		writeInternal(w, err)
		return false
	}
	if addr != "" {
		s.audit(r, "", action, addr, "target outside authorized scope", false)
		writeError(w, http.StatusForbidden, "target "+addr+" is outside the authorized scope")
		return false
	}
	return true
}

func (s *Server) approveValidationRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetValidationRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "validation run not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	// 申请之后授权范围可能已经收窄，以批准时为准
	if !s.checkScope(w, r, run.Targets, "validation.approve") {
		return
	}
	switch err := s.store.StartValidationRun(r.Context(), run.ID, userFrom(r.Context()).Username, newID()); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusConflict, "run is not awaiting approval")
	case errors.Is(err, store.ErrSelfApproval):
		writeError(w, http.StatusForbidden, err.Error())
	case err != nil:
		writeInternal(w, err)
	default:
		s.audit(r, "", "validation.start", run.ID, "approved", true)
		w.WriteHeader(http.StatusNoContent)
	}
}

// validationReport 汇总本次验证开始之后在目标上确认存在和已修复的漏洞。漏洞是实时状态，
// 之后的扫描和修复会反映在报告里。
func (s *Server) validationReport(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetValidationRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "validation run not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	findings, fixed := []model.Vuln{}, []model.Vuln{}
	counts := map[model.Severity]int{}
	if run.StartedAt != nil {
		addrs, err := scanner.ExpandTargets(run.Targets)
		if err != nil {
			writeInternal(w, err)
			return
		}
		inRun := make(map[string]bool, len(addrs))
		for _, a := range addrs {
			inRun[a.Unmap().String()] = true
		}
		vulns, err := s.store.ListVulns(r.Context(), store.VulnFilter{})
		if err != nil {
			writeInternal(w, err)
			return
		}
		for _, v := range vulns {
			switch {
			case !inRun[v.IP]:
			case v.Status == model.VulnOpen && !v.LastSeen.Before(*run.StartedAt):
				findings = append(findings, v)
				counts[v.Severity]++
			case v.Status == model.VulnFixed && v.FixedAt != nil && !v.FixedAt.Before(*run.StartedAt):
				fixed = append(fixed, v)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "counts": counts, "findings": findings, "fixed": fixed})
}

// coverageWindow：更早的自检不再算数，规则、Agent 和环境都可能已经变了。
const coverageWindow = 30 * 24 * time.Hour

type ruleCoverage struct {
	ID      model.AlertType `json:"id"`
	Name    string          `json:"name"`
	Tactic  string          `json:"tactic"`
	State   string          `json:"state"` // verified / failed / not_run / no_scenario
	LastRun *time.Time      `json:"last_run,omitempty"`
}

// coverageOf 把规则和自检结果对应起来：每个场景以最近一次有结果的自检为准，不适用和出错不算验证过。
func coverageOf(rules []alert.Rule, sims []model.Simulation, now time.Time) map[string]any {
	latest := map[string]model.Simulation{}
	var total, passed int64
	for _, sim := range sims { // 按时间倒序
		if sim.Status != model.SimPassed && sim.Status != model.SimFailed {
			continue
		}
		if sim.FinishedAt == nil || now.Sub(*sim.FinishedAt) > coverageWindow {
			continue
		}
		if _, ok := latest[sim.Scenario]; !ok {
			latest[sim.Scenario] = sim
		}
		if sim.Status == model.SimPassed {
			total += sim.LatencyMs
			passed++
		}
	}
	out := make([]ruleCoverage, 0, len(rules))
	summary := map[string]int{}
	byTactic := map[string]int{}
	for _, rule := range rules {
		c := ruleCoverage{ID: rule.ID, Name: rule.Name, Tactic: rule.Tactic, State: "no_scenario"}
		if rule.Simulation != "" {
			c.State = "not_run"
			if sim, ok := latest[rule.Simulation]; ok {
				c.State, c.LastRun = "failed", sim.FinishedAt
				if sim.Status == model.SimPassed {
					c.State = "verified"
				}
			}
		}
		summary[c.State]++
		out = append(out, c)
		for _, tactic := range strings.Split(rule.Tactic, " / ") {
			byTactic[tactic]++
		}
	}
	tactics := make([]map[string]any, 0, len(alert.Tactics))
	for _, tactic := range alert.Tactics {
		tactics = append(tactics, map[string]any{"tactic": tactic, "rules": byTactic[tactic]})
	}
	var avg int64
	if passed > 0 {
		avg = total / passed
	}
	return map[string]any{"rules": out, "summary": summary, "tactics": tactics, "avg_latency_ms": avg,
		"window_days": int(coverageWindow.Hours() / 24)}
}

func (s *Server) detectionCoverage(w http.ResponseWriter, r *http.Request) {
	sims, err := s.store.ListSimulations(r.Context(), 2000)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, coverageOf(alert.Catalog, sims, time.Now()))
}
