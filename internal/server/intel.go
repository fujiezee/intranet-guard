package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"safe/internal/model"
	"safe/internal/netintel"
	"safe/internal/store"
)

const (
	maxFeedBytes      = 32 << 20
	maxFeedIndicators = 300000
	maxManualText     = 4 << 20
)

var feedClient = &http.Client{Timeout: 60 * time.Second}

func (s *Server) intelOverview(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	list, err := s.store.ListIndicators(r.Context(), q, 500)
	if err != nil {
		writeInternal(w, err)
		return
	}
	counts, err := s.store.IntelCounts(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"indicators": list, "counts": counts, "sim_domain": store.SimIntelDomain})
}

func validSeverity(s model.Severity) bool {
	return s == model.SeverityHigh || s == model.SeverityMedium
}

func (s *Server) addIndicators(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string         `json:"text"`
		Severity model.Severity `json:"severity"`
		Note     string         `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxManualText)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validSeverity(req.Severity) || len(req.Note) > 200 {
		writeError(w, http.StatusBadRequest, "severity must be high or medium")
		return
	}
	list, err := store.ParseIntelList(strings.NewReader(req.Text), 100000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(list) == 0 {
		writeError(w, http.StatusBadRequest, "no valid IP, CIDR or domain found")
		return
	}
	added, err := s.store.AddIndicators(r.Context(), req.Severity, strings.TrimSpace(req.Note), list)
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.add", "", fmt.Sprintf("parsed=%d added=%d", len(list), added), true)
	writeJSON(w, http.StatusOK, map[string]int{"parsed": len(list), "added": added})
}

func (s *Server) deleteIndicator(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteIndicator(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "indicator not found (feed indicators are managed by their feed)")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.delete", r.PathValue("id"), "", true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.store.ListFeeds(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, feeds)
}

func (s *Server) createFeed(w http.ResponseWriter, r *http.Request) {
	var f model.IntelFeed
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeError(w, http.StatusBadRequest, "url must be http or https")
		return
	}
	f.Name = strings.TrimSpace(f.Name)
	if f.Name == "" || len(f.Name) > 64 || !validSeverity(f.Severity) {
		writeError(w, http.StatusBadRequest, "name and severity (high / medium) are required")
		return
	}
	f, err = s.store.CreateFeed(r.Context(), f)
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.feed.create", strconv.FormatInt(f.ID, 10), f.Name+" "+f.URL, true)
	if f.Enabled {
		go s.FetchFeed(context.WithoutCancel(r.Context()), f)
	}
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) updateFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.SetFeedEnabled(r.Context(), id, req.Enabled); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.feed.update", r.PathValue("id"), "enabled="+strconv.FormatBool(req.Enabled), true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteFeed(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "feed not found")
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.feed.delete", r.PathValue("id"), "", true)
	w.WriteHeader(http.StatusNoContent)
}

// refreshFeed 立即拉取一次，返回拉取后的状态（包括错误）。
func (s *Server) refreshFeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	feeds, err := s.store.ListFeeds(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	for _, f := range feeds {
		if f.ID == id {
			s.FetchFeed(r.Context(), f)
			feeds, _ = s.store.ListFeeds(r.Context())
			for _, g := range feeds {
				if g.ID == id {
					writeJSON(w, http.StatusOK, g)
					return
				}
			}
		}
	}
	writeError(w, http.StatusNotFound, "feed not found")
}

// FetchFeed 拉取订阅源并替换其条目；失败时保留旧条目并记录错误。
func (s *Server) FetchFeed(ctx context.Context, f model.IntelFeed) {
	list, err := fetchIntel(ctx, f.URL)
	if err != nil {
		slog.Warn("fetch intel feed", "feed", f.Name, "err", err)
	} else {
		slog.Info("intel feed updated", "feed", f.Name, "indicators", len(list))
	}
	if err := s.store.RecordFeedFetch(ctx, f.ID, list, err); err != nil {
		slog.Error("save intel feed", "feed", f.Name, "err", err)
	}
}

func fetchIntel(ctx context.Context, u string) ([]netintel.Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "safe-server")
	resp, err := feedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return store.ParseIntelList(io.LimitReader(resp.Body, maxFeedBytes), maxFeedIndicators)
}

func (s *Server) getNetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.NetConfig(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) setNetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg netintel.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if cfg.WorkStart < 0 || cfg.WorkStart > 23 || cfg.WorkEnd < 1 || cfg.WorkEnd > 24 || cfg.WorkStart >= cfg.WorkEnd ||
		cfg.ExfilBytes < 0 || len(cfg.Allow) > 200 {
		writeError(w, http.StatusBadRequest, "work hours must satisfy 0 <= start < end <= 24; exfil_bytes >= 0")
		return
	}
	var allow []string
	for _, a := range cfg.Allow {
		if d := netintel.NormalizeDomain(strings.TrimPrefix(a, "*.")); d != "" {
			allow = append(allow, d)
		}
	}
	cfg.Allow = allow
	if err := s.store.SetNetConfig(r.Context(), cfg); err != nil {
		writeInternal(w, err)
		return
	}
	s.audit(r, "", "intel.net_config", "", fmt.Sprintf("work=%d-%d exfil=%d allow=%d", cfg.WorkStart, cfg.WorkEnd, cfg.ExfilBytes, len(cfg.Allow)), true)
	w.WriteHeader(http.StatusNoContent)
}

// --- 探针 ---

type probeIntel struct {
	Version    int64                `json:"version"`
	Indicators []netintel.Indicator `json:"indicators"`
}

// intelPayload 缓存下发给探针的情报。订阅推荐源后有约 20 万条（JSON 约 38 MB，gzip 后约 1.5 MB），
// 情报版本变化时所有探针几乎同时来拉取：只生成一次，压缩后共用。
type intelPayload struct {
	mu      sync.Mutex
	version int64
	gz      []byte
}

func (s *Server) probeIntel(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.IntelVersion(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	s.intel.mu.Lock()
	if s.intel.gz == nil || s.intel.version != v {
		list, err := s.store.AllIndicators(r.Context())
		if err != nil {
			s.intel.mu.Unlock()
			writeInternal(w, err)
			return
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_ = json.NewEncoder(zw).Encode(probeIntel{Version: v, Indicators: list})
		_ = zw.Close()
		s.intel.gz, s.intel.version = buf.Bytes(), v
	}
	body := s.intel.gz
	s.intel.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Vary", "Accept-Encoding")
	// 探针使用 Go 默认的 HTTP 客户端，会自动请求 gzip 并解压
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(body)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		writeInternal(w, err)
		return
	}
	_, _ = io.Copy(w, zr)
}

type netFindingReport struct {
	ProbeID  string             `json:"probe_id"`
	Findings []netintel.Finding `json:"findings"`
}

func (s *Server) submitNetFindings(w http.ResponseWriter, r *http.Request) {
	var rep netFindingReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	probeID, ok := nodeIdentity(w, r, rep.ProbeID)
	if !ok {
		return
	}
	err := s.store.SaveNetFindings(r.Context(), probeID, rep.Findings)
	if errors.Is(err, store.ErrTooManyEvents) {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	} else if err != nil {
		writeInternal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
