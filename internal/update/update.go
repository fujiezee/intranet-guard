// Package update 定期检查是否有新版本发布（GitHub Releases），供控制台提示升级。
// 内网无法访问时只记录错误，不影响任何功能。
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"safe/internal/version"
)

// DefaultURL 是本项目发布页的接口地址；-update-url 为空时不检查。
const DefaultURL = "https://api.github.com/repos/fujiezee/intranet-guard/releases/latest"

type Status struct {
	Current         string     `json:"current"`
	Latest          string     `json:"latest,omitempty"`
	UpdateAvailable bool       `json:"update_available"`
	ReleaseURL      string     `json:"release_url,omitempty"`
	ReleaseNotes    string     `json:"release_notes,omitempty"`
	PublishedAt     *time.Time `json:"published_at,omitempty"`
	CheckedAt       *time.Time `json:"checked_at,omitempty"`
	CheckError      string     `json:"check_error,omitempty"`
	Disabled        bool       `json:"disabled,omitempty"`
}

type Checker struct {
	URL     string
	Current string
	HTTP    *http.Client

	mu     sync.Mutex
	status Status
}

func New(url, current string) *Checker {
	c := &Checker{URL: url, Current: current, HTTP: &http.Client{Timeout: 20 * time.Second}}
	c.status = Status{Current: current, Disabled: url == ""}
	return c
}

func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Run 启动后稍等再检查，之后每 6 小时检查一次。
func (c *Checker) Run(ctx context.Context) {
	if c.URL == "" {
		return
	}
	delay := 10 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		c.Check(ctx)
		delay = 6 * time.Hour
	}
}

func (c *Checker) Check(ctx context.Context) {
	now := time.Now().UTC()
	st := Status{Current: c.Current, CheckedAt: &now}
	rel, err := c.fetch(ctx)
	switch {
	case err != nil:
		st.CheckError = err.Error()
		slog.Debug("update check failed", "err", err) // 内网通常无法访问，不作为警告
	case rel != nil:
		st.Latest = strings.TrimPrefix(rel.TagName, "v")
		st.ReleaseURL = rel.HTMLURL
		st.ReleaseNotes = rel.Body
		if len(st.ReleaseNotes) > 8000 {
			st.ReleaseNotes = st.ReleaseNotes[:8000] + "\n\n……（完整内容见发布页）"
		}
		if !rel.PublishedAt.IsZero() {
			st.PublishedAt = &rel.PublishedAt
		}
		st.UpdateAvailable = version.Older(c.Current, st.Latest)
	}
	c.mu.Lock()
	c.status = st
	c.mu.Unlock()
	if st.UpdateAvailable {
		slog.Info("new version available", "current", c.Current, "latest", st.Latest, "url", st.ReleaseURL)
	}
}

type release struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
}

// fetch 返回最新发布；还没有任何发布时返回 nil。
func (c *Checker) fetch(ctx context.Context) (*release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "safe-server/"+c.Current)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	var r release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
