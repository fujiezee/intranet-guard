package netintel

import (
	"net/netip"
	"slices"
	"strings"
)

// Indicator 是一条威胁情报。
type Indicator struct {
	Type     string `json:"type"` // ip / cidr / domain
	Value    string `json:"value"`
	Source   string `json:"source"`
	Severity string `json:"severity"` // high / medium
	Note     string `json:"note,omitempty"`
}

// Intel 是用于匹配的情报集合，构建后只读，可以在多个 goroutine 中共享。
type Intel struct {
	ips      map[netip.Addr]Indicator
	prefixes map[netip.Prefix]Indicator
	bits     []int // prefixes 中出现过的掩码长度，从长到短
	domains  map[string]Indicator
}

// specialUse 是内网和特殊用途地址段（RFC 6890 等）。公开情报源常把它们列为 bogon，
// 作为情报会让所有内网地址都命中。文档示例段（TEST-NET-1/2/3）不在其中。
var specialUse = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), // 基准测试段，也常被代理软件用作虚拟 IP
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/127"), // 未指定地址和 ::1
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// SpecialUse 判断网段是否与内网或特殊用途地址段重叠，这样的条目不能作为情报。
func SpecialUse(p netip.Prefix) bool {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	for _, s := range specialUse {
		if s.Overlaps(p) {
			return true
		}
	}
	return false
}

// SpecialUseAddr 判断单个地址是否属于内网或特殊用途地址段。
func SpecialUseAddr(a netip.Addr) bool {
	a = a.Unmap()
	return SpecialUse(netip.PrefixFrom(a, a.BitLen()))
}

// NewIntel 构建情报集合，无法解析的条目和内网地址被忽略（修复前导入的内网网段也不再命中）。
func NewIntel(list []Indicator) *Intel {
	in := &Intel{ips: map[netip.Addr]Indicator{}, prefixes: map[netip.Prefix]Indicator{}, domains: map[string]Indicator{}}
	for _, ind := range list {
		switch ind.Type {
		case "ip":
			if a, err := netip.ParseAddr(ind.Value); err == nil && !SpecialUseAddr(a) {
				in.ips[a.Unmap()] = ind
			}
		case "cidr":
			if p, err := netip.ParsePrefix(ind.Value); err == nil && !SpecialUse(p) {
				if _, dup := in.prefixes[p.Masked()]; !dup {
					in.prefixes[p.Masked()] = ind
				}
				if !slices.Contains(in.bits, p.Bits()) {
					in.bits = append(in.bits, p.Bits())
				}
			}
		case "domain":
			if d := NormalizeDomain(ind.Value); d != "" {
				in.domains[d] = ind
			}
		}
	}
	slices.Sort(in.bits)
	slices.Reverse(in.bits)
	return in
}

// Len 返回条目数。
func (in *Intel) Len() int {
	if in == nil {
		return 0
	}
	return len(in.ips) + len(in.prefixes) + len(in.domains)
}

// MatchIP 返回命中的情报，网段之间取最长匹配。公开情报源有数千个网段，
// 按掩码长度逐个查表（最多几十次），而不是逐条比较。
func (in *Intel) MatchIP(a netip.Addr) (Indicator, bool) {
	if in == nil || !a.IsValid() {
		return Indicator{}, false
	}
	if ind, ok := in.ips[a]; ok {
		return ind, true
	}
	for _, bits := range in.bits {
		if bits > a.BitLen() {
			continue
		}
		p, _ := a.Prefix(bits)
		if ind, ok := in.prefixes[p]; ok {
			return ind, true
		}
	}
	return Indicator{}, false
}

// MatchDomain 按后缀匹配：情报 evil.com 命中 evil.com 和 a.b.evil.com，不命中 notevil.com。
func (in *Intel) MatchDomain(name string) (Indicator, bool) {
	if in == nil || name == "" {
		return Indicator{}, false
	}
	name = NormalizeDomain(name)
	for {
		if ind, ok := in.domains[name]; ok {
			return ind, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return Indicator{}, false
		}
		name = name[i+1:]
	}
}

// NormalizeDomain 转为小写并去掉末尾的点；不像域名的返回空字符串。
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " /:@*") {
		return ""
	}
	return s
}

// 常见的二级公共后缀：注册域名要多取一级（example.com.cn、example.co.uk）
var secondLevel = map[string]bool{"com": true, "net": true, "org": true, "gov": true, "edu": true, "ac": true, "co": true, "or": true, "ne": true, "go": true}

// RegisteredDomain 近似计算注册域名（eTLD+1），不依赖完整的公共后缀列表。
func RegisteredDomain(name string) string {
	labels := strings.Split(name, ".")
	n := len(labels)
	switch {
	case n <= 2:
		return name
	case len(labels[n-1]) == 2 && secondLevel[labels[n-2]]:
		return strings.Join(labels[n-3:], ".")
	default:
		return strings.Join(labels[n-2:], ".")
	}
}
