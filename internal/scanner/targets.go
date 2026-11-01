package scanner

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MaxTargets 限制单个任务展开后的地址数量（一个 /16），防止误配置导致的大范围扫描。
const MaxTargets = 65536

// ExpandTargets 把 IP、CIDR、a.b.c.d-e 范围展开为 IPv4 地址列表。
// CIDR 会去掉网络地址和广播地址（/31、/32 除外）。
func ExpandTargets(specs []string) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	add := func(a netip.Addr) error {
		if seen[a] {
			return nil
		}
		if len(out) >= MaxTargets {
			return fmt.Errorf("targets exceed limit of %d addresses", MaxTargets)
		}
		seen[a] = true
		out = append(out, a)
		return nil
	}

	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		switch {
		case strings.Contains(spec, "/"):
			p, err := netip.ParsePrefix(spec)
			if err != nil || !p.Addr().Is4() {
				return nil, fmt.Errorf("invalid IPv4 CIDR %q", spec)
			}
			p = p.Masked()
			if p.Bits() < 16 {
				return nil, fmt.Errorf("CIDR %q is larger than /16", spec)
			}
			first, last := p.Addr(), lastAddr(p)
			if p.Bits() < 31 {
				first, last = first.Next(), last.Prev()
			}
			for a := first; a.Compare(last) <= 0; a = a.Next() {
				if err := add(a); err != nil {
					return nil, err
				}
			}
		case strings.Contains(spec, "-"):
			startStr, endStr, _ := strings.Cut(spec, "-")
			start, err := netip.ParseAddr(startStr)
			if err != nil || !start.Is4() {
				return nil, fmt.Errorf("invalid range %q", spec)
			}
			end, err := strconv.Atoi(endStr)
			b := start.As4()
			if err != nil || end < int(b[3]) || end > 255 {
				return nil, fmt.Errorf("invalid range %q", spec)
			}
			for i := int(b[3]); i <= end; i++ {
				b[3] = byte(i)
				if err := add(netip.AddrFrom4(b)); err != nil {
					return nil, err
				}
			}
		default:
			a, err := netip.ParseAddr(spec)
			if err != nil || !a.Is4() {
				return nil, fmt.Errorf("invalid IPv4 address %q", spec)
			}
			if err := add(a); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= ^uint32(0) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
