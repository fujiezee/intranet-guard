// Package server 实现管理中心的 HTTP API。
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/pki"
	"safe/internal/scanner"
	"safe/internal/store"
	"safe/internal/update"
)

type Config struct {
	CA     *pki.CA // 内部 CA，用于节点注册与 mTLS
	WebDir string  // 前端构建产物目录（web/dist），为空则不托管前端

	// TrustedProxies 是可信反向代理的地址段：来自这些地址的请求按 X-Forwarded-For 识别真实客户端 IP。
	TrustedProxies []netip.Prefix
	// 节点一键安装：InstallPin 是节点接入端口的公钥指纹（curl --pinnedpubkey），NodePort 是该端口，
	// DistDir 存放可下载的探针 / Agent 程序（safe-agent-linux-amd64 等）。
	InstallPin string
	NodePort   int
	DistDir    string
	// NodeURLs 是高可用部署时全部实例的节点接入地址（https://host:port），写入一键安装的节点配置
	NodeURLs []string
	// NodeHosts 是节点接入证书中的主机名和 IP（节点可以用这些地址连接）
	NodeHosts []string
	// Updates 提供新版本检查结果，为 nil 时不检查
	Updates *update.Checker
	// ConsoleScheme、ConsolePort 用于在节点接入端口的首页给出控制台地址
	ConsoleScheme string
	ConsolePort   int

	// HSTS 为 true 时（控制台经 HTTPS 提供）下发 Strict-Transport-Security，要求浏览器以后只用 HTTPS 访问。
	HSTS bool

	// 旧版共享 token（已弃用）：设置后控制台端口上仍接受 token 认证的探针 / Agent，方便迁移。
	// 这种方式无法区分节点身份，迁移完成后应清空。
	ProbeToken string
	AgentToken string
}

type Server struct {
	cfg     Config
	store   *store.Store
	mux     *http.ServeMux // 控制台与管理 API
	nodeMux *http.ServeMux // 节点接入（mTLS）
	limiter *loginLimiter
	release releaseCache // Agent 升级用的版本清单与策略缓存
}

func New(cfg Config, st *store.Store) *Server {
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux(), nodeMux: http.NewServeMux(),
		limiter: &loginLimiter{failures: map[string][]time.Time{}}}

	admin := func(h http.HandlerFunc) http.Handler { return s.requireRole(model.RoleAdmin, h) }
	viewer := func(h http.HandlerFunc) http.Handler { return s.requireRole(model.RoleViewer, h) }

	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.Handle("POST /api/v1/auth/logout", viewer(s.logout))
	s.mux.Handle("GET /api/v1/auth/me", viewer(s.me))
	s.mux.Handle("POST /api/v1/auth/password", viewer(s.changePassword))

	s.mux.Handle("GET /api/v1/stats", viewer(s.stats))
	s.mux.Handle("POST /api/v1/tasks", admin(s.createTask))
	s.mux.Handle("GET /api/v1/tasks", viewer(s.listTasks))
	s.mux.Handle("GET /api/v1/tasks/{id}", viewer(s.getTask))
	s.mux.Handle("GET /api/v1/assets", viewer(s.listAssets))
	s.mux.Handle("GET /api/v1/assets/{ip}", viewer(s.getAsset))
	s.mux.Handle("GET /api/v1/alerts", viewer(s.listAlerts))
	s.mux.Handle("POST /api/v1/alerts/{id}/ack", admin(s.ackAlert))

	s.mux.Handle("GET /api/v1/vulns", viewer(s.listVulns))
	s.mux.Handle("POST /api/v1/vulns/{id}/status", admin(s.setVulnStatus))

	s.mux.Handle("GET /api/v1/rules", viewer(s.listRules))
	s.mux.Handle("GET /api/v1/honeypots", viewer(s.listHoneypots))
	s.mux.Handle("PUT /api/v1/honeypots/{probe}", admin(s.setHoneypot))
	s.mux.Handle("GET /api/v1/honeypot-events", viewer(s.listHoneypotEvents))
	s.mux.Handle("GET /api/v1/simulations", viewer(s.listSimulations))
	s.mux.Handle("POST /api/v1/simulations", admin(s.createSimulations))

	s.mux.Handle("GET /api/v1/intel", viewer(s.intelOverview))
	s.mux.Handle("POST /api/v1/intel/indicators", admin(s.addIndicators))
	s.mux.Handle("DELETE /api/v1/intel/indicators/{id}", admin(s.deleteIndicator))
	s.mux.Handle("GET /api/v1/intel/feeds", viewer(s.listFeeds))
	s.mux.Handle("POST /api/v1/intel/feeds", admin(s.createFeed))
	s.mux.Handle("PATCH /api/v1/intel/feeds/{id}", admin(s.updateFeed))
	s.mux.Handle("DELETE /api/v1/intel/feeds/{id}", admin(s.deleteFeed))
	s.mux.Handle("POST /api/v1/intel/feeds/{id}/refresh", admin(s.refreshFeed))
	s.mux.Handle("GET /api/v1/intel/net-config", viewer(s.getNetConfig))
	s.mux.Handle("PUT /api/v1/intel/net-config", admin(s.setNetConfig))

	s.mux.Handle("GET /api/v1/incidents", viewer(s.listIncidents))
	s.mux.Handle("GET /api/v1/incidents/{id}", viewer(s.getIncident))
	s.mux.Handle("PATCH /api/v1/incidents/{id}", admin(s.updateIncident))
	s.mux.Handle("POST /api/v1/incidents/{id}/notes", admin(s.addIncidentNote))
	s.mux.Handle("PUT /api/v1/assets/{ip}/meta", admin(s.setAssetMeta))
	s.mux.Handle("GET /api/v1/version", viewer(s.versionInfo))
	s.mux.Handle("GET /api/v1/upgrades", viewer(s.listUpgrades))
	s.mux.Handle("PUT /api/v1/upgrades/policy", admin(s.setUpgradePolicy))
	s.mux.Handle("POST /api/v1/upgrades", admin(s.queueUpgrades))
	s.mux.Handle("GET /api/v1/groups", viewer(s.listGroups))
	s.mux.Handle("POST /api/v1/groups", admin(s.saveGroup))
	s.mux.Handle("PUT /api/v1/groups/{id}", admin(s.saveGroup))
	s.mux.Handle("DELETE /api/v1/groups/{id}", admin(s.deleteGroup))

	s.mux.Handle("GET /api/v1/actions", viewer(s.listActions))
	s.mux.Handle("POST /api/v1/actions", admin(s.createAction))
	s.mux.Handle("POST /api/v1/actions/{id}/approve", admin(s.approveAction))
	s.mux.Handle("POST /api/v1/actions/{id}/rollback", admin(s.rollbackAction))

	s.mux.Handle("GET /api/v1/agents", viewer(s.listAgents))
	s.mux.Handle("GET /api/v1/host-events", viewer(s.listHostEvents))

	s.mux.Handle("GET /api/v1/ids/events", viewer(s.listIDSEvents))
	s.mux.Handle("GET /api/v1/ids/suppressions", viewer(s.listSuppressions))
	s.mux.Handle("POST /api/v1/ids/suppressions", admin(s.createSuppression))
	s.mux.Handle("DELETE /api/v1/ids/suppressions/{id}", admin(s.deleteSuppression))

	s.mux.Handle("GET /api/v1/audit", admin(s.listAudit))
	s.mux.Handle("GET /api/v1/notify-channels", admin(s.listChannels))
	s.mux.Handle("POST /api/v1/notify-channels", admin(s.createChannel))
	s.mux.Handle("POST /api/v1/notify-channels/{id}/enabled", admin(s.setChannelEnabled))
	s.mux.Handle("POST /api/v1/notify-channels/{id}/test", admin(s.testChannel))
	s.mux.Handle("DELETE /api/v1/notify-channels/{id}", admin(s.deleteChannel))

	s.mux.Handle("GET /api/v1/users", admin(s.listUsers))
	s.mux.Handle("POST /api/v1/users", admin(s.createUser))
	s.mux.Handle("DELETE /api/v1/users/{id}", admin(s.deleteUser))
	s.mux.Handle("GET /api/v1/api-tokens", admin(s.listAPITokens))
	s.mux.Handle("POST /api/v1/api-tokens", admin(s.createAPIToken))
	s.mux.Handle("DELETE /api/v1/api-tokens/{id}", admin(s.deleteAPIToken))

	s.mux.Handle("GET /api/v1/nodes", admin(s.listNodes))
	s.mux.Handle("GET /api/v1/install-info", admin(s.installInfoHandler))
	s.mux.Handle("POST /api/v1/nodes/{kind}/{id}/revoke", admin(s.revokeNode))
	s.mux.Handle("GET /api/v1/enroll-tokens", admin(s.listEnrollTokens))
	s.mux.Handle("POST /api/v1/enroll-tokens", admin(s.createEnrollToken))
	s.mux.Handle("DELETE /api/v1/enroll-tokens/{id}", admin(s.deleteEnrollToken))

	nodeRoutes := func(mux *http.ServeMux, probe, agent func(http.HandlerFunc) http.Handler) {
		mux.Handle("GET /api/v1/probe/tasks", probe(s.claimTasks))
		mux.Handle("POST /api/v1/probe/reports", probe(s.submitReport))
		mux.Handle("POST /api/v1/probe/ids-events", probe(s.submitIDSEvents))
		mux.Handle("POST /api/v1/probe/config", probe(s.probeConfig))
		mux.Handle("POST /api/v1/probe/honeypot-events", probe(s.submitHoneypotEvents))
		mux.Handle("GET /api/v1/probe/intel", probe(s.probeIntel))
		mux.Handle("POST /api/v1/probe/net-findings", probe(s.submitNetFindings))
		mux.Handle("POST /api/v1/agent/report", agent(s.agentReport))
		mux.Handle("GET /api/v1/agent/whoami", agent(s.whoami)) // 升级前新版本自检用
	}
	nodeRoutes(s.nodeMux,
		func(h http.HandlerFunc) http.Handler { return s.requireNode(model.NodeProbe, h) },
		func(h http.HandlerFunc) http.Handler { return s.requireNode(model.NodeAgent, h) })
	s.nodeMux.HandleFunc("GET /api/v1/ca", s.getCA)
	s.nodeMux.HandleFunc("POST /api/v1/enroll", s.enroll)
	s.nodeMux.HandleFunc("POST /api/v1/node/renew", s.renew)
	s.nodeMux.HandleFunc("GET /install/{script}", s.installScript)
	s.nodeMux.HandleFunc("GET /i/{token}", s.installByToken)
	s.nodeMux.HandleFunc("GET /download/{file}", s.download)
	s.nodeMux.HandleFunc("GET /{$}", s.nodeIndex)
	s.nodeMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not found") })

	if cfg.ProbeToken != "" || cfg.AgentToken != "" {
		nodeRoutes(s.mux,
			func(h http.HandlerFunc) http.Handler { return requireToken(cfg.ProbeToken, h) },
			func(h http.HandlerFunc) http.Handler { return requireToken(cfg.AgentToken, h) })
	}

	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	if cfg.WebDir != "" {
		s.mux.Handle("/", spaHandler(cfg.WebDir))
	}
	return s
}

// spaHandler 托管前端静态文件，其余路径（含目录，避免列目录且与 /assets 等前端路由冲突）
// 回退到 index.html 交给前端路由处理。
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fi, err := os.Stat(filepath.Join(dir, filepath.Clean("/"+r.URL.Path))); err != nil || !fi.Mode().IsRegular() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// NodeHandler 是节点接入端口的处理器，需配合 NodeTLSConfig 使用。
func (s *Server) NodeHandler() http.Handler { return s.nodeMux }

// 告警和事件含攻击者可控的文本，会话令牌存在 localStorage：即使出现 XSS，也不能加载外部脚本或把数据发到外部。
// Element Plus 依赖内联样式。
const contentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

const maxRequestBody = 64 << 20 // 与节点上报的上限一致

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	if s.cfg.HSTS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	s.mux.ServeHTTP(w, r)
	slog.Debug("request", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start))
}

func requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type createTaskRequest struct {
	ProbeID      string         `json:"probe_id"`
	Targets      []string       `json:"targets"`
	Ports        []int          `json:"ports"`
	Baseline     bool           `json:"baseline"`
	Kind         model.TaskKind `json:"kind"`
	WeakPassword bool           `json:"weak_password"`
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ProbeID == "" || len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "probe_id and targets are required")
		return
	}
	// 在管理中心提前校验，避免把无效或超大范围的任务下发给探针。
	if _, err := scanner.ExpandTargets(req.Targets); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Kind == "" {
		req.Kind = model.TaskDiscovery
	}
	if req.Kind != model.TaskDiscovery && req.Kind != model.TaskVuln {
		writeError(w, http.StatusBadRequest, "kind must be discovery or vuln")
		return
	}
	if req.WeakPassword && req.Kind != model.TaskVuln {
		writeError(w, http.StatusBadRequest, "weak_password requires kind vuln")
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

	now := time.Now().UTC()
	t := model.ScanTask{
		ID: newID(), ProbeID: req.ProbeID, Targets: req.Targets, Ports: req.Ports, Baseline: req.Baseline,
		Kind: req.Kind, WeakPassword: req.WeakPassword,
		Status: model.TaskPending, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateTask(r.Context(), t); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "task.create", t.ID, fmt.Sprintf("probe=%s kind=%s weak_password=%v baseline=%v targets=%v",
		t.ProbeID, t.Kind, t.WeakPassword, t.Baseline, t.Targets), true)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) listTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.store.ListTasks(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.store.ListAssets(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAsset(r.Context(), r.PathValue("ip"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	status := model.AlertStatus(r.URL.Query().Get("status"))
	if status != "" && status != model.AlertOpen && status != model.AlertAcked {
		writeError(w, http.StatusBadRequest, "status must be open or acked")
		return
	}
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "limit must be within 1-5000")
			return
		}
		limit = n
	}
	alerts, err := s.store.ListAlerts(r.Context(), status, limit)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	var req struct {
		FalsePositive bool   `json:"false_positive"`
		Reason        string `json:"reason"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if req.FalsePositive && strings.TrimSpace(req.Reason) == "" {
		writeError(w, http.StatusBadRequest, "reason is required when marking a false positive")
		return
	}
	err = s.store.AckAlert(r.Context(), id, userFrom(r.Context()).Username, req.FalsePositive, strings.TrimSpace(req.Reason))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	detail := ""
	if req.FalsePositive {
		detail = "false_positive: " + req.Reason
	}
	s.audit(r, "", "alert.ack", strconv.FormatInt(id, 10), detail, true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) claimTasks(w http.ResponseWriter, r *http.Request) {
	probeID, ok := nodeIdentity(w, r, r.URL.Query().Get("probe_id"))
	if !ok {
		return
	}
	tasks, err := s.store.ClaimTasks(r.Context(), probeID)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) submitReport(w http.ResponseWriter, r *http.Request) {
	var rep model.ScanReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var ok bool
	if rep.ProbeID, ok = nodeIdentity(w, r, rep.ProbeID); !ok {
		return
	}
	err := s.store.SaveReport(r.Context(), rep)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "task not found for this probe")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	slog.Info("scan report saved", "task", rep.TaskID, "probe", rep.ProbeID, "assets", len(rep.Assets))
	w.WriteHeader(http.StatusNoContent)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeInternal(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) {
		// 客户端已断开（节点重启、请求超时放弃）：不是服务端故障，不记为错误
		slog.Debug("request canceled by client", "err", err)
		writeError(w, http.StatusServiceUnavailable, "request canceled")
		return
	}
	slog.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}
