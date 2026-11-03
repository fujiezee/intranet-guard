package netintel

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config 是分析参数，由管理中心随探针配置下发。
type Config struct {
	Allow      []string `json:"allow"`       // 不做 DNS 隧道 / 心跳分析的域名后缀（如杀毒软件的 DNS 查询）
	WorkStart  int      `json:"work_start"`  // 工作时间开始（时，探针本地时区）
	WorkEnd    int      `json:"work_end"`    // 工作时间结束（时）
	ExfilBytes int64    `json:"exfil_bytes"` // 非工作时间单台主机每小时外发超过此字节数视为疑似外传
}

// DefaultConfig 是未配置时使用的参数。
func DefaultConfig() Config {
	return Config{Allow: []string{"in-addr.arpa", "ip6.arpa", "local", "spamhaus.org", "sophosxl.net", "mcafee.com"},
		WorkStart: 7, WorkEnd: 22, ExfilBytes: 1 << 30}
}

// Finding 是一条分析结果。SrcIP 是内网中的相关主机，告警关联到它。
type Finding struct {
	Kind     string    `json:"kind"` // intel / dga / dns_tunnel / beacon / exfil
	Severity string    `json:"severity"`
	SrcIP    string    `json:"src_ip"`
	Peer     string    `json:"peer"` // 对端域名或地址
	Detail   string    `json:"detail"`
	Time     time.Time `json:"time"`
}

const (
	dgaWindow       = 10 * time.Minute
	dgaThreshold    = 10 // 窗口内随机外观且解析失败的不同域名数
	tunnelWindow    = 10 * time.Minute
	tunnelDistinct  = 50 // 同一注册域名下不同子域名数
	tunnelAvgLen    = 30 // 子域名部分的平均长度
	beaconWindow    = 2 * time.Hour
	beaconMinCount  = 12
	beaconMaxCV     = 0.2 // 间隔的变异系数（标准差 / 平均值）
	beaconMinPeriod = 10 * time.Second
	beaconMaxPeriod = time.Hour
	maxKeys         = 50000 // 每类状态最多跟踪的键，防止内存无限增长
)

var quietFor = map[string]time.Duration{"intel": 30 * time.Minute, "dga": time.Hour, "dns_tunnel": time.Hour, "beacon": 6 * time.Hour, "exfil": time.Hour}

// Analyzer 保存各检测的窗口状态。Observe 与 Tick 可以在不同 goroutine 中调用。
type Analyzer struct {
	mu     sync.Mutex
	cfg    Config
	intel  *Intel
	loc    *time.Location
	quiet  map[string]time.Time
	nx     map[netip.Addr]map[string]time.Time // 主机 → 随机外观且解析失败的域名 → 时间
	tunnel map[string]*tunnelState             // 主机|注册域名
	flows  map[string][]time.Time              // 主机|目标|端口|协议 → 连接开始时间
	exfil  map[string]map[netip.Addr]int64     // 主机|小时 → 目标 → 字节
	exfilT map[string]time.Time                // 主机|小时 → 该小时开始时间
}

type tunnelState struct {
	names map[string]time.Time
}

func NewAnalyzer(cfg Config, intel *Intel, loc *time.Location) *Analyzer {
	if loc == nil {
		loc = time.Local
	}
	return &Analyzer{cfg: cfg, intel: intel, loc: loc, quiet: map[string]time.Time{}, nx: map[netip.Addr]map[string]time.Time{},
		tunnel: map[string]*tunnelState{}, flows: map[string][]time.Time{}, exfil: map[string]map[netip.Addr]int64{}, exfilT: map[string]time.Time{}}
}

// SetIntel 替换情报集合（情报版本变化时）。
func (a *Analyzer) SetIntel(in *Intel) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.intel = in
}

// SetConfig 替换分析参数。
func (a *Analyzer) SetConfig(cfg Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
}

func (a *Analyzer) allowed(name string) bool {
	for _, s := range a.cfg.Allow {
		s = strings.ToLower(strings.TrimPrefix(s, "."))
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// once 返回 true 表示该结果在冷却期内第一次出现，应当上报。
func (a *Analyzer) once(kind, key string, t time.Time) bool {
	k := kind + "|" + key
	// 记录可能乱序到达，按时间差的绝对值判断
	if last, ok := a.quiet[k]; ok && t.Sub(last).Abs() < quietFor[kind] {
		return false
	}
	if len(a.quiet) > maxKeys {
		a.quiet = map[string]time.Time{}
	}
	a.quiet[k] = t
	return true
}

// Observe 处理一条记录，返回立即可判定的结果（情报命中）。窗口类检测在 Tick 中输出。
func (a *Analyzer) Observe(e Event) []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Finding
	switch e.Type {
	case "dns":
		client := e.SrcIP
		if e.Response { // 应答由 DNS 服务器发往客户端
			client = e.DstIP
		}
		if !e.Response {
			if ind, ok := a.intel.MatchDomain(e.QName); ok && a.once("intel", client.String()+"|"+e.QName, e.Time) {
				out = append(out, a.intelFinding(client, e.QName, "查询了情报中的域名", ind, e.Time))
			}
			a.observeTunnel(client, e.QName, e.Time)
		} else if e.RCode == "NXDOMAIN" && DGALike(e.QName) {
			if a.nx[client] == nil {
				if len(a.nx) > maxKeys {
					a.nx = map[netip.Addr]map[string]time.Time{}
				}
				a.nx[client] = map[string]time.Time{}
			}
			a.nx[client][e.QName] = e.Time
		}
	case "tls", "http":
		if e.Host != "" && Internal(e.SrcIP) {
			if ind, ok := a.intel.MatchDomain(e.Host); ok && a.once("intel", e.SrcIP.String()+"|"+e.Host, e.Time) {
				what := map[string]string{"tls": "TLS 连接（SNI）", "http": "HTTP 访问"}[e.Type]
				out = append(out, a.intelFinding(e.SrcIP, e.Host, what+"情报中的域名", ind, e.Time))
			}
		}
	case "flow":
		// 内网 → 情报地址，或情报地址 → 内网（入站访问）
		for _, pair := range [][2]netip.Addr{{e.SrcIP, e.DstIP}, {e.DstIP, e.SrcIP}} {
			host, peer := pair[0], pair[1]
			if !Internal(host) || Internal(peer) {
				continue
			}
			if ind, ok := a.intel.MatchIP(peer); ok && a.once("intel", host.String()+"|"+peer.String(), e.Time) {
				dir := "连接了情报中的地址"
				if host == e.DstIP {
					dir = "被情报中的地址访问"
				}
				out = append(out, a.intelFinding(host, fmt.Sprintf("%s:%d", peer, e.DstPort), dir, ind, e.Time))
			}
		}
		// 心跳、外传只看发往公网的流量：组播 / 广播（SSDP、mDNS 等）也是周期性的，但不出内网
		if Internal(e.SrcIP) && !SpecialUseAddr(e.DstIP) {
			a.observeFlow(e)
		}
	}
	return out
}

func (a *Analyzer) intelFinding(host netip.Addr, peer, what string, ind Indicator, t time.Time) Finding {
	sev := ind.Severity
	if sev != "medium" {
		sev = "high"
	}
	detail := fmt.Sprintf("%s %s %s（情报来源：%s", host, what, peer, ind.Source)
	if ind.Note != "" {
		detail += "，" + ind.Note
	}
	return Finding{Kind: "intel", Severity: sev, SrcIP: host.String(), Peer: peer, Detail: detail + "）", Time: t}
}

func (a *Analyzer) observeTunnel(client netip.Addr, name string, t time.Time) {
	reg := RegisteredDomain(name)
	if reg == name || a.allowed(name) {
		return
	}
	key := client.String() + "|" + reg
	st := a.tunnel[key]
	if st == nil {
		if len(a.tunnel) > maxKeys {
			a.tunnel = map[string]*tunnelState{}
		}
		st = &tunnelState{names: map[string]time.Time{}}
		a.tunnel[key] = st
	}
	if len(st.names) < 2000 {
		st.names[name] = t
	}
}

func (a *Analyzer) observeFlow(e Event) {
	if e.DstPort == 53 || e.DstPort == 123 { // DNS、NTP 本来就是周期性的
		return
	}
	start := e.FlowStart
	if start.IsZero() {
		start = e.Time
	}
	key := fmt.Sprintf("%s|%s|%d|%s", e.SrcIP, e.DstIP, e.DstPort, e.Proto)
	if _, ok := a.flows[key]; !ok && len(a.flows) > maxKeys {
		a.flows = map[string][]time.Time{}
	}
	if fl := a.flows[key]; len(fl) < 500 {
		a.flows[key] = append(fl, start)
	}

	// 非工作时间外发流量：按主机、小时汇总
	local := start.In(a.loc)
	if h := local.Hour(); h >= a.cfg.WorkStart && h < a.cfg.WorkEnd {
		return
	}
	hour := local.Truncate(time.Hour)
	hk := e.SrcIP.String() + "|" + hour.Format("2006010215")
	if a.exfil[hk] == nil {
		if len(a.exfil) > maxKeys {
			a.exfil, a.exfilT = map[string]map[netip.Addr]int64{}, map[string]time.Time{}
		}
		a.exfil[hk] = map[netip.Addr]int64{}
		a.exfilT[hk] = hour
	}
	a.exfil[hk][e.DstIP] += e.BytesToServer
}

// Tick 评估窗口类检测并清理过期状态，建议每分钟调用一次。
func (a *Analyzer) Tick(now time.Time) []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Finding

	for client, names := range a.nx {
		var recent []string
		for n, t := range names {
			if now.Sub(t) > dgaWindow {
				delete(names, n)
				continue
			}
			recent = append(recent, n)
		}
		if len(names) == 0 {
			delete(a.nx, client)
		}
		if len(recent) >= dgaThreshold && a.once("dga", client.String(), now) {
			sort.Strings(recent)
			out = append(out, Finding{Kind: "dga", Severity: "high", SrcIP: client.String(), Time: now, Peer: recent[0],
				Detail: fmt.Sprintf("%s 在 %d 分钟内查询了 %d 个随机外观且不存在的域名（DGA 恶意软件寻找控制服务器的特征），例如 %s",
					client, int(dgaWindow.Minutes()), len(recent), strings.Join(recent[:min(5, len(recent))], "、"))})
		}
	}

	for key, st := range a.tunnel {
		total := 0
		for n, t := range st.names {
			if now.Sub(t) > tunnelWindow {
				delete(st.names, n)
				continue
			}
		}
		if len(st.names) == 0 {
			delete(a.tunnel, key)
			continue
		}
		client, reg, _ := strings.Cut(key, "|")
		var sample string
		for n := range st.names {
			total += len(n) - len(reg) - 1
			if len(n) > len(sample) {
				sample = n
			}
		}
		if avg := total / len(st.names); len(st.names) >= tunnelDistinct && avg >= tunnelAvgLen && a.once("dns_tunnel", key, now) {
			out = append(out, Finding{Kind: "dns_tunnel", Severity: "high", SrcIP: client, Peer: reg, Time: now,
				Detail: fmt.Sprintf("%s 在 %d 分钟内向 %s 查询了 %d 个不同的长子域名（平均 %d 字符），疑似 DNS 隧道外传或控制，例如 %s",
					client, int(tunnelWindow.Minutes()), reg, len(st.names), avg, truncate(sample, 120))})
		}
	}

	for key, starts := range a.flows {
		kept := starts[:0]
		for _, t := range starts {
			if now.Sub(t) <= beaconWindow {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(a.flows, key)
			continue
		}
		a.flows[key] = kept
		if period, cv, ok := beaconStats(kept); ok && a.once("beacon", key, now) {
			parts := strings.Split(key, "|")
			src, dst, port := parts[0], parts[1], parts[2]
			sev := "medium"
			peer := dst + ":" + port
			detail := fmt.Sprintf("%s 每隔约 %s 连接一次 %s（%s，%d 次，间隔波动 %.0f%%），符合 C2 心跳特征；也可能是软件更新或监控程序，请核实",
				src, period.Round(time.Second), peer, parts[3], len(kept), cv*100)
			if ind, ok := a.intel.MatchIP(netip.MustParseAddr(dst)); ok {
				sev = "high"
				detail += "；目标在威胁情报中（" + ind.Source + "）"
			}
			out = append(out, Finding{Kind: "beacon", Severity: sev, SrcIP: src, Peer: peer, Detail: detail, Time: now})
		}
	}

	for hk, dsts := range a.exfil {
		hourStart := a.exfilT[hk]
		if now.Sub(hourStart) > 3*time.Hour {
			delete(a.exfil, hk)
			delete(a.exfilT, hk)
			continue
		}
		var total int64
		type dstBytes struct {
			ip netip.Addr
			n  int64
		}
		var list []dstBytes
		for ip, n := range dsts {
			total += n
			list = append(list, dstBytes{ip, n})
		}
		if total < a.cfg.ExfilBytes || a.cfg.ExfilBytes <= 0 || !a.once("exfil", hk, now) {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		var top []string
		for _, d := range list[:min(3, len(list))] {
			top = append(top, fmt.Sprintf("%s %s", d.ip, humanBytes(d.n)))
		}
		src, _, _ := strings.Cut(hk, "|")
		out = append(out, Finding{Kind: "exfil", Severity: "medium", SrcIP: src, Peer: list[0].ip.String(), Time: now,
			Detail: fmt.Sprintf("%s 在非工作时间（%s 起的 1 小时内）向外网发送了 %s，主要目标：%s；疑似数据外传，也可能是备份或同步任务",
				src, hourStart.Format("01-02 15:04"), humanBytes(total), strings.Join(top, "、"))})
	}
	return out
}

// beaconStats 判断连接时间是否呈固定周期：去掉最大、最小各 10% 的间隔后，变异系数不超过阈值。
func beaconStats(starts []time.Time) (time.Duration, float64, bool) {
	if len(starts) < beaconMinCount {
		return 0, 0, false
	}
	ts := append([]time.Time(nil), starts...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var iv []float64
	for i := 1; i < len(ts); i++ {
		if d := ts[i].Sub(ts[i-1]).Seconds(); d > 0.5 { // 同一时刻的多个连接（并发）不计
			iv = append(iv, d)
		}
	}
	if len(iv) < beaconMinCount-1 {
		return 0, 0, false
	}
	sort.Float64s(iv)
	trim := len(iv) / 10
	iv = iv[trim : len(iv)-trim]
	var sum float64
	for _, v := range iv {
		sum += v
	}
	mean := sum / float64(len(iv))
	var sq float64
	for _, v := range iv {
		sq += (v - mean) * (v - mean)
	}
	cv := math.Sqrt(sq/float64(len(iv))) / mean
	period := time.Duration(mean * float64(time.Second))
	return period, cv, cv <= beaconMaxCV && period >= beaconMinPeriod && period <= beaconMaxPeriod
}

// DGALike 判断域名的主体部分是否像随机生成的：足够长、字符熵高，且元音少或数字多。
func DGALike(name string) bool {
	reg := RegisteredDomain(name)
	label, _, _ := strings.Cut(reg, ".")
	if len(label) < 10 {
		return false
	}
	counts := map[rune]int{}
	vowels, digits := 0, 0
	for _, r := range label {
		counts[r]++
		switch {
		case strings.ContainsRune("aeiou", r):
			vowels++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / float64(len(label))
		entropy -= p * math.Log2(p)
	}
	n := float64(len(label))
	// 短字符串的熵上限是 log2(长度)，按长度取相对阈值，而不是固定值
	return entropy >= math.Min(0.8*math.Log2(n), 3.5) && (float64(vowels)/n < 0.25 || float64(digits)/n > 0.2)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", n/1024)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
