package netintel

import (
	"net/netip"
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
	prefixes []prefixIndicator
	domains  map[string]Indicator
}

type prefixIndicator struct {
	prefix netip.Prefix
	ind    Indicator
}

// NewIntel 构建情报集合，无法解析的条目被忽略。
func NewIntel(list []Indicator) *Intel {
	in := &Intel{ips: map[netip.Addr]Indicator{}, domains: map[string]Indicator{}}
	for _, ind := range list {
		switch ind.Type {
		case "ip":
			if a, err := netip.ParseAddr(ind.Value); err == nil {
				in.ips[a.Unmap()] = ind
			}
		case "cidr":
			if p, err := netip.ParsePrefix(ind.Value); err == nil {
				in.prefixes = append(in.prefixes, prefixIndicator{p.Masked(), ind})
			}
		case "domain":
			if d := NormalizeDomain(ind.Value); d != "" {
				in.domains[d] = ind
			}
		}
	}
	return in
}

// Len 返回条目数。
func (in *Intel) Len() int {
	if in == nil {
		return 0
	}
	return len(in.ips) + len(in.prefixes) + len(in.domains)
}

// MatchIP 返回命中的情报。网段情报通常很少，线性查找即可。
func (in *Intel) MatchIP(a netip.Addr) (Indicator, bool) {
	if in == nil || !a.IsValid() {
		return Indicator{}, false
	}
	if ind, ok := in.ips[a]; ok {
		return ind, true
	}
	for _, p := range in.prefixes {
		if p.prefix.Contains(a) {
			return p.ind, true
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
