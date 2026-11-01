// Package scanner 实现无需 root 权限的 TCP 主动扫描：主机存活、开放端口、Banner。
package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"safe/internal/model"
)

// DefaultPorts 是企业内网常见的高价值服务端口。
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 1433, 1521,
	2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 11211, 27017,
}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap",
	443: "https", 445: "smb", 1433: "mssql", 1521: "oracle", 2049: "nfs",
	2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

type Options struct {
	Ports       []int
	Concurrency int           // 同时进行的 TCP 连接数
	Timeout     time.Duration // 单次连接超时
}

func (o *Options) defaults() {
	if len(o.Ports) == 0 {
		o.Ports = DefaultPorts
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 512
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
}

type probeResult struct {
	alive  bool // 收到 RST 也说明主机在线
	open   bool
	banner string
}

// Scan 对目标的每个端口发起 TCP 连接，返回存活主机及其开放端口。
func Scan(ctx context.Context, targets []netip.Addr, opts Options) []model.Asset {
	opts.defaults()

	type job struct {
		addr netip.Addr
		port int
	}
	jobs := make(chan job)
	var (
		mu      sync.Mutex
		results = make(map[netip.Addr]*model.Asset)
		wg      sync.WaitGroup
	)

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := probe(ctx, j.addr, j.port, opts.Timeout)
				if !r.alive {
					continue
				}
				mu.Lock()
				a, ok := results[j.addr]
				if !ok {
					a = &model.Asset{IP: j.addr.String(), Ports: []model.Port{}}
					results[j.addr] = a
				}
				if r.open {
					a.Ports = append(a.Ports, model.Port{
						Port: j.port, Proto: "tcp", Service: guessService(j.port, r.banner), Banner: r.banner,
					})
				}
				mu.Unlock()
			}
		}()
	}

feed:
	for _, addr := range targets {
		for _, port := range opts.Ports {
			select {
			case jobs <- job{addr, port}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()

	assets := make([]model.Asset, 0, len(results))
	for _, a := range results {
		sort.Slice(a.Ports, func(i, j int) bool { return a.Ports[i].Port < a.Ports[j].Port })
		if names, err := net.DefaultResolver.LookupAddr(ctx, a.IP); err == nil && len(names) > 0 {
			a.Hostname = strings.TrimSuffix(names[0], ".")
		}
		assets = append(assets, *a)
	}
	sort.Slice(assets, func(i, j int) bool {
		return netip.MustParseAddr(assets[i].IP).Less(netip.MustParseAddr(assets[j].IP))
	})
	return assets
}

func probe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) probeResult {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	if err != nil {
		return probeResult{alive: errors.Is(err, syscall.ECONNREFUSED)}
	}
	defer conn.Close()
	return probeResult{alive: true, open: true, banner: grabBanner(conn, timeout)}
}

// grabBanner 读取服务主动发送的欢迎信息（SSH、FTP、SMTP、MySQL 等）。
func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return sanitize(buf[:n])
}

func sanitize(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else if c == '\n' || c == '\r' {
			sb.WriteByte(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}

func guessService(port int, banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp"), strings.Contains(lower, "esmtp"):
		return "smtp"
	case strings.Contains(lower, "redis"):
		return "redis"
	}
	return serviceNames[port]
}
