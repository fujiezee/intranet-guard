package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"safe/internal/model"
	signing "safe/internal/release"
	"safe/internal/store"
	"safe/internal/update"
)

// agentRelease 是管理中心可以分发的 Agent 版本：来自安装包中的 downloads/manifest.json 和各平台程序。
type agentRelease struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"-"` // 文件名 → SHA-256
	Sigs    map[string]string `json:"-"` // 文件名 → 离线签名（<文件名>.sig），Agent 验证，管理中心只转发
}

// ReleaseKeys 是构建时写入的发布公钥，只用于在控制台提前显示签名状态：是否接受升级始终由 Agent 自己判断。
var ReleaseKeys = ""

// 版本清单的签名状态。
const (
	signatureVerified  = "verified"  // 所有平台的程序都通过验证
	signatureUnchecked = "unchecked" // 都有签名，但这个管理中心没有公钥，无法提前验证
	signatureMissing   = "missing"   // 有程序缺少签名
	signatureInvalid   = "invalid"   // 有程序的签名不正确
)

func (r agentRelease) signatureStatus() string {
	if len(r.Files) == 0 {
		return ""
	}
	status := signatureVerified
	for file, sum := range r.Files {
		sig := r.Sigs[file]
		if sig == "" {
			return signatureMissing
		}
		switch err := signing.Verify(ReleaseKeys, r.Version, file, sum, sig); {
		case errors.Is(err, signing.ErrNoKey):
			status = signatureUnchecked
		case err != nil:
			return signatureInvalid
		}
	}
	return status
}

type releaseCache struct {
	mu      sync.Mutex
	rel     agentRelease
	modTime time.Time
	policy  store.UpgradePolicy
	polAt   time.Time
}

var agentBinary = regexp.MustCompile(`^safe-agent-(linux|windows)-(amd64|arm64)(\.exe)?$`)

// agentRelease 读取版本清单；清单或程序更新（升级管理中心、替换 downloads 目录）后自动重新计算。
func (s *Server) agentRelease() (agentRelease, error) {
	if s.cfg.DistDir == "" {
		return agentRelease{}, nil
	}
	manifest := filepath.Join(s.cfg.DistDir, "manifest.json")
	fi, err := os.Stat(manifest)
	if errors.Is(err, os.ErrNotExist) {
		return agentRelease{}, nil // 旧版安装包没有清单：不支持控制台升级
	} else if err != nil {
		return agentRelease{}, err
	}
	c := &s.release
	c.mu.Lock()
	defer c.mu.Unlock()
	if fi.ModTime().Equal(c.modTime) && c.rel.Version != "" {
		return c.rel, nil
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return agentRelease{}, err
	}
	var rel agentRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return agentRelease{}, fmt.Errorf("manifest.json: %w", err)
	}
	rel.Files, rel.Sigs = map[string]string{}, map[string]string{}
	entries, _ := os.ReadDir(s.cfg.DistDir)
	for _, e := range entries {
		if !agentBinary.MatchString(e.Name()) {
			continue
		}
		f, err := os.Open(filepath.Join(s.cfg.DistDir, e.Name()))
		if err != nil {
			return agentRelease{}, err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return agentRelease{}, err
		}
		rel.Files[e.Name()] = hex.EncodeToString(h.Sum(nil))
		if sig, err := os.ReadFile(filepath.Join(s.cfg.DistDir, e.Name()+".sig")); err == nil {
			rel.Sigs[e.Name()] = strings.TrimSpace(string(sig))
		}
	}
	c.rel, c.modTime = rel, fi.ModTime()
	return rel, nil
}

// upgradePolicy 缓存 10 秒：每次上报都要用，不必每次查库。
func (s *Server) upgradePolicy(r *http.Request) (store.UpgradePolicy, error) {
	c := &s.release
	c.mu.Lock()
	if time.Since(c.polAt) < 10*time.Second {
		p := c.policy
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()
	p, err := s.store.UpgradePolicy(r.Context())
	if err != nil {
		return p, err
	}
	c.mu.Lock()
	c.policy, c.polAt = p, time.Now()
	c.mu.Unlock()
	return p, nil
}

func (s *Server) invalidatePolicy() {
	s.release.mu.Lock()
	s.release.polAt = time.Time{}
	s.release.mu.Unlock()
}

// agentFile 返回该平台的 Agent 程序文件名（AgentInfo.OS 形如 linux/amd64）。
func agentFile(osArch string) string {
	goos, arch, _ := strings.Cut(osArch, "/")
	name := "safe-agent-" + goos + "-" + arch
	if goos == "windows" {
		name += ".exe"
	}
	if !agentBinary.MatchString(name) {
		return ""
	}
	return name
}

// upgradeCommand 在 Agent 上报时判断是否下发升级指令。
func (s *Server) upgradeCommand(r *http.Request, a model.AgentInfo) (*model.AgentCommand, error) {
	rel, err := s.agentRelease()
	if err != nil {
		return nil, err
	}
	p, err := s.upgradePolicy(r)
	if err != nil {
		return nil, err
	}
	attempt, target, err := s.store.NextUpgrade(r.Context(), a.ID, a.Version, rel.Version, p)
	if err != nil || attempt == "" {
		return nil, err
	}
	file := agentFile(a.OS)
	sum := rel.Files[file]
	if sum == "" {
		return nil, s.store.FailUpgrade(r.Context(), a.ID, attempt, "管理中心没有该平台（"+a.OS+"）的 Agent 程序")
	}
	return &model.AgentCommand{ID: attempt, Type: "upgrade",
		Params: map[string]string{"version": target, "file": file, "sha256": sum, "signature": rel.Sigs[file]}}, nil
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	id, ok := nodeIdentity(w, r, "")
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

type upgradeAgent struct {
	ID       string              `json:"id"`
	Hostname string              `json:"hostname"`
	OS       string              `json:"os"`
	Version  string              `json:"version"`
	Status   model.AgentStatus   `json:"status"`
	Outdated bool                `json:"outdated"`           // 与管理中心提供的版本不同
	Verifies bool                `json:"verifies_signature"` // Agent 自报：这个版本会验证发布签名
	Upgrade  *store.AgentUpgrade `json:"upgrade,omitempty"`
}

func (s *Server) listUpgrades(w http.ResponseWriter, r *http.Request) {
	rel, err := s.agentRelease()
	if err != nil {
		writeInternal(w, err)
		return
	}
	p, err := s.store.UpgradePolicy(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	ups, err := s.store.ListUpgrades(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	out := []upgradeAgent{}
	for _, a := range agents {
		ua := upgradeAgent{ID: a.ID, Hostname: a.Hostname, OS: a.OS, Version: a.Version, Status: a.Status,
			Outdated: rel.Version != "" && a.Version != rel.Version, Verifies: slices.Contains(a.Capabilities, "signed_upgrade")}
		if u, ok := ups[a.ID]; ok {
			ua.Upgrade = &u
		}
		out = append(out, ua)
	}
	files := []string{}
	for f := range rel.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	writeJSON(w, http.StatusOK, map[string]any{
		"latest": map[string]any{"version": rel.Version, "files": files, "signature": rel.signatureStatus()}, "policy": p, "agents": out})
}

func (s *Server) setUpgradePolicy(w http.ResponseWriter, r *http.Request) {
	var p store.UpgradePolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if p.Mode != "manual" && p.Mode != "auto" {
		writeError(w, http.StatusBadRequest, "mode must be manual or auto")
		return
	}
	if p.MaxConcurrent < 1 || p.MaxConcurrent > 1000 || p.MaxFailures < 1 || p.MaxFailures > 100 {
		writeError(w, http.StatusBadRequest, "max_concurrent must be 1-1000 and max_failures 1-100")
		return
	}
	if !p.Paused {
		p.PausedReason = ""
	}
	if err := s.store.SetUpgradePolicy(r.Context(), p); err != nil {
		writeInternal(w, err)
		return
	}
	s.invalidatePolicy()
	s.audit(r, "", "upgrade.policy", "", fmt.Sprintf("mode=%s max_concurrent=%d max_failures=%d paused=%v",
		p.Mode, p.MaxConcurrent, p.MaxFailures, p.Paused), true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) queueUpgrades(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.AgentIDs) == 0 || len(req.AgentIDs) > 10000 {
		writeError(w, http.StatusBadRequest, "agent_ids is required")
		return
	}
	for _, id := range req.AgentIDs {
		if !validNodeID.MatchString(id) {
			writeError(w, http.StatusBadRequest, "invalid agent id "+id)
			return
		}
	}
	rel, err := s.agentRelease()
	if err != nil {
		writeInternal(w, err)
		return
	}
	if rel.Version == "" {
		writeError(w, http.StatusBadRequest, "no agent release available (deploy the management server from a release bundle)")
		return
	}
	n, err := s.store.QueueUpgrades(r.Context(), req.AgentIDs, rel.Version, userFrom(r.Context()).Username)
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "upgrade.queue", rel.Version, fmt.Sprintf("agents=%d queued=%d", len(req.AgentIDs), n), true)
	writeJSON(w, http.StatusOK, map[string]int{"queued": n})
}

// Version 是管理中心的版本号，由 make release 通过 -ldflags 写入；直接 go build 时为 dev。
var Version = "dev"

// versionInfo：控制台显示的当前版本、最新发布（用于提示升级）和可分发给节点的 Agent 版本。
func (s *Server) versionInfo(w http.ResponseWriter, r *http.Request) {
	st := update.Status{Current: Version, Disabled: true}
	if s.cfg.Updates != nil {
		st = s.cfg.Updates.Status()
	}
	rel, _ := s.agentRelease()
	writeJSON(w, http.StatusOK, map[string]any{"server": st, "agent_latest": rel.Version})
}
