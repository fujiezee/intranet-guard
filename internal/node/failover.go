package node

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// ParseServers 解析逗号分隔的管理中心地址（高可用部署时有多个实例）。
func ParseServers(list string) ([]*url.URL, error) {
	var out []*url.URL
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimRight(strings.TrimSpace(s), "/")
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("invalid server URL " + s + " (https://host:port expected)")
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, errors.New("no server URL")
	}
	return out, nil
}

// failover 把发往第一个管理中心地址的请求转发到当前可用的实例：连接失败（无法建立连接、TLS 握手失败、
// 连接中断）时依次换下一个实例重试，成功后记住该实例。HTTP 错误状态码不切换——那是实例给出的明确答复。
// 业务代码始终用第一个地址拼 URL，不需要感知有几个实例。
type failover struct {
	base    http.RoundTripper
	servers []*url.URL
	cur     atomic.Int32
}

func (f *failover) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(f.servers) < 2 || req.URL.Host != f.servers[0].Host {
		return f.base.RoundTrip(req)
	}
	start := int(f.cur.Load())
	var lastErr error
	for i := range f.servers {
		idx := (start + i) % len(f.servers)
		r := req.Clone(req.Context())
		r.URL.Scheme, r.URL.Host, r.Host = f.servers[idx].Scheme, f.servers[idx].Host, ""
		if i > 0 && req.Body != nil {
			if req.GetBody == nil {
				return nil, lastErr // 请求体无法重放，不能重试
			}
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = body
		}
		resp, err := f.base.RoundTrip(r)
		if err == nil {
			if idx != start {
				f.cur.Store(int32(idx))
				slogFailover(f.servers[start], f.servers[idx])
			}
			return resp, nil
		}
		lastErr = err
		if req.Context().Err() != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func slogFailover(from, to *url.URL) {
	slog.Warn("management server unreachable, switched to another instance", "from", from.Host, "to", to.Host)
}

// CloseIdleConnections 转发给底层连接池：证书续期后要关闭旧连接，下次请求才会用新证书重新握手。
// http.Client.CloseIdleConnections 只在 Transport 实现了这个方法时才生效。
func (f *failover) CloseIdleConnections() {
	if c, ok := f.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
