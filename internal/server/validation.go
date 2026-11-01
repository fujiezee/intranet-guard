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
		Ports: req.Ports, WeakPassword: req.WeakPassword, CreatedBy: u})
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "validation.create", run.ID, fmt.Sprintf("probe=%s weak_password=%v targets=%v", run.ProbeID, run.WeakPassword, run.Targets), true)
	if !run.WeakPassword { // 低风险：发起的管理员就是批准人
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
