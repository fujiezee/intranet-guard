// Package honeypot 在探针上运行低交互蜜罐：伪装成常见服务，记录连接和登录尝试，但从不真正放行。
// 内网正常业务不会访问蜜罐，任何访问都是高置信度的入侵或扫描信号。
package honeypot

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"safe/internal/model"
)

// SimulationMarker 是攻击模拟自检发送的首行：带此标记的连接即使来自本机也会上报，并关联到对应的自检。
const SimulationMarker = "SAFE-SIMULATION "

var reSimID = regexp.MustCompile(`^sim-[0-9a-f]{8}$`)

const (
	maxConns       = 256              // 同时处理的连接数上限
	maxEventsPerIP = 30               // 每个来源每分钟最多上报的事件数，防止被刷爆
	connTimeout    = 30 * time.Second // 单个连接最长保持时间
	peekWait       = 300 * time.Millisecond
)

// Types 是支持的伪装服务类型。
var Types = map[string]bool{"ssh": true, "ftp": true, "telnet": true, "mysql": true, "redis": true, "http": true, "tcp": true}

type Manager struct {
	emit func(model.HoneypotEvent)

	mu        sync.Mutex
	listeners map[int]*listener // 按端口
	ignore    []netip.Prefix
	local     map[netip.Addr]bool
	status    map[int]string // 端口 → "listening" 或错误信息
	sem       chan struct{}
	rate      map[string]*rateEntry
}

type listener struct {
	svc model.HoneypotService
	ln  net.Listener
}

type rateEntry struct {
	window time.Time
	n      int
}

// New 创建蜜罐管理器，emit 在每次有效访问时被调用（并发安全由调用方保证或自行加锁）。
func New(emit func(model.HoneypotEvent)) *Manager {
	return &Manager{
		emit: emit, listeners: map[int]*listener{}, status: map[int]string{},
		sem: make(chan struct{}, maxConns), rate: map[string]*rateEntry{},
	}
}

// Apply 按配置启停监听：新增的端口开始监听，移除或停用的端口关闭。
func (m *Manager) Apply(cfg model.HoneypotConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ignore = m.ignore[:0]
	for _, c := range cfg.IgnoreSources {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			m.ignore = append(m.ignore, p.Masked())
		} else if a, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil {
			m.ignore = append(m.ignore, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	m.local = localAddrs()

	want := map[int]model.HoneypotService{}
	if cfg.Enabled {
		for _, s := range cfg.Services {
			if Types[s.Type] && s.Port > 0 && s.Port < 65536 {
				want[s.Port] = s
			}
		}
	}
	for port, l := range m.listeners {
		if w, ok := want[port]; !ok || w.Type != l.svc.Type {
			l.ln.Close()
			delete(m.listeners, port)
			delete(m.status, port)
		}
	}
	for port, svc := range want {
		if _, ok := m.listeners[port]; ok {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			m.status[port] = err.Error()
			continue
		}
		m.status[port] = "listening"
		l := &listener{svc: svc, ln: ln}
		m.listeners[port] = l
		go m.serve(l)
		slog.Info("honeypot listening", "service", svc.Type, "port", port)
	}
	for port := range m.status {
		if _, ok := want[port]; !ok {
			delete(m.status, port)
		}
	}
}

// Status 返回各端口的监听状态，随配置请求上报，便于在控制台发现端口冲突。
func (m *Manager) Status() map[int]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int]string, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

// Close 关闭所有监听。
func (m *Manager) Close() { m.Apply(model.HoneypotConfig{}) }

func (m *Manager) serve(l *listener) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		select {
		case m.sem <- struct{}{}:
		default:
			conn.Close() // 连接过多，直接丢弃
			continue
		}
		go func() {
			defer func() { <-m.sem }()
			defer conn.Close()
			m.handle(l.svc, conn)
		}()
	}
}

// session 是一次连接的上下文：服务处理函数通过 report 上报事件。
type session struct {
	m       *Manager
	svc     model.HoneypotService
	conn    net.Conn
	r       *bufio.Reader
	src     netip.AddrPort
	simID   string
	ignored bool
}

func (s *session) report(ev model.HoneypotEvent) {
	if s.ignored {
		return
	}
	ev.Time = time.Now().UTC()
	ev.Service, ev.Port = s.svc.Type, s.svc.Port
	ev.SrcIP, ev.SrcPort = s.src.Addr().Unmap().String(), int(s.src.Port())
	ev.SimulationID = s.simID
	if ev.Password != "" {
		ev.Password = mask(ev.Password)
	}
	if s.simID == "" && !s.m.allow(ev.SrcIP) {
		return
	}
	s.m.emit(ev)
}

func (m *Manager) allow(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e := m.rate[ip]
	if e == nil || now.Sub(e.window) > time.Minute {
		if len(m.rate) > 10000 {
			m.rate = map[string]*rateEntry{}
		}
		e = &rateEntry{window: now}
		m.rate[ip] = e
	}
	e.n++
	return e.n <= maxEventsPerIP
}

func (m *Manager) ignored(a netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	a = a.Unmap()
	if m.local[a] {
		return true // 探针自己的扫描任务会扫到本机蜜罐端口
	}
	for _, p := range m.ignore {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (m *Manager) handle(svc model.HoneypotService, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(connTimeout))
	src, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	s := &session{m: m, svc: svc, conn: conn, r: bufio.NewReader(conn), src: src}

	// 先短暂等待客户端数据：自检连接会立即发送标记；对"服务端先说话"的协议（SSH、FTP 等），
	// 真实客户端此时在等横幅，不会发送任何数据，等待 300ms 后照常进入协议处理。
	_ = conn.SetReadDeadline(time.Now().Add(peekWait))
	if b, err := s.r.Peek(len(SimulationMarker)); err == nil && string(b) == SimulationMarker {
		line, _ := s.r.ReadString('\n')
		if id := strings.TrimSpace(strings.TrimPrefix(line, SimulationMarker)); reSimID.MatchString(id) {
			s.simID = id
			s.report(model.HoneypotEvent{Detail: "攻击模拟自检 " + id})
			conn.Write([]byte("OK\n"))
			return
		}
	}
	_ = conn.SetDeadline(time.Now().Add(connTimeout))
	s.ignored = m.ignored(src.Addr())

	switch svc.Type {
	case "ssh":
		serveSSH(s)
	case "ftp":
		serveFTP(s)
	case "telnet":
		serveTelnet(s)
	case "mysql":
		serveMySQL(s)
	case "redis":
		serveRedis(s)
	case "http":
		serveHTTP(s)
	default:
		serveTCP(s)
	}
}

// bufConn 让已经预读过的数据继续被协议库读取。
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func mask(p string) string {
	if p == "" {
		return ""
	}
	r := []rune(p)
	return string(r[0]) + strings.Repeat("*", len(r)-1)
}

// printable 去掉控制字符并截断，避免把二进制数据写进告警。
func printable(b []byte, max int) string {
	var sb strings.Builder
	for _, c := range string(b) {
		if sb.Len() >= max {
			sb.WriteString("…")
			break
		}
		if c >= 0x20 && c != 0x7f && c != 0xfffd {
			sb.WriteRune(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			sb.WriteByte(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}

func localAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out[ip.Unmap()] = true // 只匹配本机实际配置的地址，不是整个网段
			}
		}
	}
	return out
}

// Run 是给探针用的便捷函数：定期拉取配置并应用，ctx 结束时关闭全部监听。
func Run(ctx context.Context, m *Manager, fetch func(context.Context, map[int]string) (model.HoneypotConfig, error), every time.Duration) {
	defer m.Close()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		before := m.Status()
		if cfg, err := fetch(ctx, before); err != nil {
			slog.Warn("fetch probe config", "err", err)
		} else {
			m.Apply(cfg)
			// 监听状态变了就立即再上报一次，控制台不必等下一个周期才看到端口是否启动成功
			if after := m.Status(); !sameStatus(before, after) {
				if _, err := fetch(ctx, after); err != nil {
					slog.Warn("report honeypot status", "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func sameStatus(a, b map[int]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
