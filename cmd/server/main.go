// safe-server 是管理中心：接收探针上报、管理资产与扫描任务。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"safe/internal/chstore"
	"safe/internal/model"
	"safe/internal/notify"
	"safe/internal/pki"
	"safe/internal/server"
	"safe/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "safe.db", "SQLite file path, or postgres://user:pass@host:5432/dbname for PostgreSQL")
	migrateFrom := flag.String("migrate-from", "", "copy all data from this SQLite file into -db, then exit")
	eventsDB := flag.String("events-db", os.Getenv("SAFE_EVENTS_DB"),
		"store host / IDS events in ClickHouse: clickhouse://user:pass@host:8123/dbname (default: $SAFE_EVENTS_DB, else main database)")
	importEvents := flag.Bool("import-events", false, "copy existing events from -db into -events-db, then exit")
	webDir := flag.String("web", "web/dist", "frontend build directory (empty to disable)")
	nodeAddr := flag.String("node-addr", ":8443", "mTLS listen address for probes and agents")
	nodeHosts := flag.String("node-hosts", "", "comma-separated DNS names / IPs nodes use to reach this server (default: hostname and local IPs)")
	pkiDir := flag.String("pki-dir", "pki", "directory holding the internal CA")
	taskTimeout := flag.Duration("task-timeout", 6*time.Hour, "mark running scan tasks as failed after this long without a result")
	flag.Parse()

	if *migrateFrom != "" {
		os.Exit(runMigration(*migrateFrom, *dbPath))
	}
	if *importEvents {
		os.Exit(runImportEvents(*dbPath, *eventsDB))
	}

	cfg := server.Config{ProbeToken: os.Getenv("SAFE_PROBE_TOKEN"), AgentToken: os.Getenv("SAFE_AGENT_TOKEN"), WebDir: *webDir}
	if cfg.ProbeToken != "" || cfg.AgentToken != "" {
		if (cfg.ProbeToken != "" && len(cfg.ProbeToken) < 16) || (cfg.AgentToken != "" && len(cfg.AgentToken) < 16) {
			slog.Error("legacy SAFE_PROBE_TOKEN / SAFE_AGENT_TOKEN must be at least 16 characters")
			os.Exit(1)
		}
		if cfg.ProbeToken == cfg.AgentToken {
			slog.Error("SAFE_PROBE_TOKEN and SAFE_AGENT_TOKEN must be different")
			os.Exit(1)
		}
		slog.Warn("legacy shared tokens enabled on the console port: node identities cannot be verified; " +
			"enroll nodes with certificates and unset SAFE_PROBE_TOKEN / SAFE_AGENT_TOKEN")
	}

	ca, created, err := pki.LoadOrCreateCA(*pkiDir)
	if err != nil {
		slog.Error("load CA", "err", err)
		os.Exit(1)
	}
	if created {
		slog.Info("created internal CA; back up the pki directory", "dir", *pkiDir)
	}
	cfg.CA = ca
	hosts := defaultNodeHosts()
	if *nodeHosts != "" {
		hosts = strings.Split(*nodeHosts, ",")
	}
	nodeTLS, err := server.NodeTLSConfig(ca, hosts)
	if err != nil {
		slog.Error("node TLS", "err", err)
		os.Exit(1)
	}
	if cfg.WebDir != "" {
		if _, err := os.Stat(cfg.WebDir); err != nil {
			slog.Warn("frontend directory not found, serving API only", "dir", cfg.WebDir)
			cfg.WebDir = ""
		}
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	if *eventsDB != "" {
		es, err := chstore.Open(context.Background(), *eventsDB, eventRetention)
		if err != nil {
			slog.Error("open events database", "err", err)
			os.Exit(1)
		}
		st.UseEventStore(es)
		slog.Info("events stored in ClickHouse", "dsn", redactDSN(*eventsDB), "retention", eventRetention)
	}

	if err := bootstrapAdmin(st); err != nil {
		slog.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}

	handler := server.New(cfg, st)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	nodeSrv := &http.Server{
		Addr:              *nodeAddr,
		Handler:           handler.NodeHandler(),
		TLSConfig:         nodeTLS,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go maintenance(ctx, st, *taskTimeout)
	go notify.Run(ctx, st, 10*time.Second)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = nodeSrv.Shutdown(shutdownCtx)
	}()

	go func() {
		slog.Info("node endpoint listening (mTLS)", "addr", *nodeAddr, "hosts", hosts, "ca_fingerprint", ca.Fingerprint())
		if err := nodeSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("node server", "err", err)
			stop()
		}
	}()

	slog.Info("safe-server listening", "addr", *addr, "db", redactDSN(*dbPath))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
}

// bootstrapAdmin 在没有任何用户时创建初始管理员 admin。
// 密码取自 SAFE_INIT_ADMIN_PASSWORD；未设置则随机生成并只在日志里打印一次。
func bootstrapAdmin(st *store.Store) error {
	ctx := context.Background()
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	pw := os.Getenv("SAFE_INIT_ADMIN_PASSWORD")
	generated := pw == ""
	if generated {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		pw = base64.RawURLEncoding.EncodeToString(b)
	}
	hash, err := server.HashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, "admin", hash, model.RoleAdmin); err != nil {
		return err
	}
	if generated {
		slog.Warn("created initial admin user; change this password after first login", "username", "admin", "password", pw)
	} else {
		slog.Info("created initial admin user from SAFE_INIT_ADMIN_PASSWORD", "username", "admin")
	}
	return nil
}

const (
	agentOfflineAfter = 3 * time.Minute     // Agent 默认 30 秒上报一次，连续多次缺失视为离线
	eventRetention    = 90 * 24 * time.Hour // 主机事件、IDS 事件保留时长
)

// maintenance 定期执行：Agent 离线检测、超时任务清理（每分钟），过期会话与历史事件清理（每小时）。
func maintenance(ctx context.Context, st *store.Store, taskTimeout time.Duration) {
	minute := time.NewTicker(time.Minute)
	hour := time.NewTicker(time.Hour)
	defer minute.Stop()
	defer hour.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minute.C:
			if n, err := st.MarkOfflineAgents(ctx, time.Now().Add(-agentOfflineAfter)); err != nil {
				slog.Warn("mark offline agents", "err", err)
			} else if n > 0 {
				slog.Warn("agents went offline", "count", n)
			}
			if ids, err := st.FailStaleTasks(ctx, time.Now().Add(-taskTimeout)); err != nil {
				slog.Warn("fail stale tasks", "err", err)
			} else if len(ids) > 0 {
				slog.Warn("scan tasks timed out", "tasks", ids, "timeout", taskTimeout)
			}
		case <-hour.C:
			if err := st.DeleteExpiredSessions(ctx); err != nil {
				slog.Warn("delete expired sessions", "err", err)
			}
			if n, err := st.PurgeEvents(ctx, time.Now().Add(-eventRetention)); err != nil {
				slog.Warn("purge events", "err", err)
			} else if n > 0 {
				slog.Info("purged old events", "count", n)
			}
		}
	}
}

// defaultNodeHosts 返回本机主机名和所有 IP，作为节点接入证书的 SAN。
func defaultNodeHosts() []string {
	hosts := []string{"localhost", "127.0.0.1"}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
				hosts = append(hosts, ipn.IP.String())
			}
		}
	}
	return hosts
}

// runMigration 把 SQLite 数据复制到新数据库（通常是 PostgreSQL）。目标库必须为空。
func runMigration(from, to string) int {
	src, err := store.Open(from)
	if err != nil {
		slog.Error("open source", "err", err)
		return 1
	}
	defer src.Close()
	dst, err := store.Open(to)
	if err != nil {
		slog.Error("open destination", "err", err)
		return 1
	}
	defer dst.Close()
	counts, err := dst.CopyFrom(context.Background(), src)
	if err != nil {
		slog.Error("migration failed; destination left unchanged", "err", err)
		return 1
	}
	for table, n := range counts {
		slog.Info("copied", "table", table, "rows", n)
	}
	slog.Info("migration complete", "from", from, "to", redactDSN(to))
	return 0
}

// redactDSN 隐藏连接串中的密码，避免写进日志。
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

// runImportEvents 把主库中的历史事件导入 ClickHouse。目标库已有事件时拒绝执行，避免重复导入。
func runImportEvents(dbPath, eventsDSN string) int {
	if eventsDSN == "" {
		slog.Error("-import-events requires -events-db or SAFE_EVENTS_DB")
		return 1
	}
	ctx := context.Background()
	st, err := store.Open(dbPath)
	if err != nil {
		slog.Error("open database", "err", err)
		return 1
	}
	defer st.Close()
	es, err := chstore.Open(ctx, eventsDSN, eventRetention)
	if err != nil {
		slog.Error("open events database", "err", err)
		return 1
	}
	if n, err := es.Count(ctx); err != nil {
		slog.Error("count events", "err", err)
		return 1
	} else if n > 0 {
		slog.Error("events database already contains events; refusing to import twice", "rows", n)
		return 1
	}
	hosts, ids, err := st.ExportEvents(ctx, es, 5000)
	if err != nil {
		slog.Error("import events", "imported_host_events", hosts, "imported_ids_events", ids, "err", err)
		return 1
	}
	slog.Info("events imported; the copies in the main database are left untouched", "host_events", hosts, "ids_events", ids)
	return 0
}
