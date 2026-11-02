package netintel

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

func TestParseEve(t *testing.T) {
	for _, tc := range []struct {
		line string
		want Event
	}{
		{`{"timestamp":"2026-11-01T09:00:00.000000+0800","event_type":"dns","src_ip":"10.0.0.5","dest_ip":"10.0.0.53","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"Evil.COM."}}`,
			Event{Type: "dns", QName: "evil.com"}},
		{`{"timestamp":"2026-11-01T09:00:00.000000+0800","event_type":"dns","src_ip":"10.0.0.53","dest_ip":"10.0.0.5","proto":"UDP","dns":{"version":3,"type":"response","rcode":"NXDOMAIN","queries":[{"rrname":"qx7z.example","rrtype":"A"}]}}`,
			Event{Type: "dns", QName: "qx7z.example", Response: true, RCode: "NXDOMAIN"}},
		{`{"timestamp":"2026-11-01T09:00:00.000000+0800","event_type":"tls","src_ip":"10.0.0.5","dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","tls":{"sni":"C2.Example.net"}}`,
			Event{Type: "tls", Host: "c2.example.net"}},
		{`{"timestamp":"2026-11-01T09:00:00.000000+0800","event_type":"flow","src_ip":"10.0.0.5","dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","flow":{"bytes_toserver":1234,"start":"2026-11-01T08:59:00.000000+0800"}}`,
			Event{Type: "flow", BytesToServer: 1234}},
	} {
		e, ok := ParseEve([]byte(tc.line))
		if !ok || e.Type != tc.want.Type || e.QName != tc.want.QName || e.Response != tc.want.Response || e.RCode != tc.want.RCode ||
			e.Host != tc.want.Host || e.BytesToServer != tc.want.BytesToServer || e.Time.IsZero() {
			t.Errorf("ParseEve(%s) = %+v", tc.line, e)
		}
	}
	for _, line := range []string{`{"event_type":"alert"}`, `{"event_type":"stats"}`, `not json`, `{"event_type":"dns","src_ip":"x","dest_ip":"y","dns":{}}`} {
		if _, ok := ParseEve([]byte(line)); ok {
			t.Errorf("parsed %s", line)
		}
	}
}

func TestIntelMatch(t *testing.T) {
	in := NewIntel([]Indicator{{Type: "ip", Value: "203.0.113.9"}, {Type: "cidr", Value: "198.51.100.0/24"},
		{Type: "domain", Value: "Evil.com."}, {Type: "domain", Value: "bad value with space"}})
	if in.Len() != 3 {
		t.Errorf("len = %d", in.Len())
	}
	for v, want := range map[string]bool{"203.0.113.9": true, "198.51.100.77": true, "203.0.113.10": false} {
		if _, ok := in.MatchIP(netip.MustParseAddr(v)); ok != want {
			t.Errorf("MatchIP(%s) = %v", v, ok)
		}
	}
	for v, want := range map[string]bool{"evil.com": true, "a.b.EVIL.com": true, "notevil.com": false, "evil.com.cn": false} {
		if _, ok := in.MatchDomain(v); ok != want {
			t.Errorf("MatchDomain(%s) = %v", v, ok)
		}
	}
	if RegisteredDomain("a.b.example.com.cn") != "example.com.cn" || RegisteredDomain("x.y.example.org") != "example.org" {
		t.Error("registered domain")
	}
}

func TestSpecialUse(t *testing.T) {
	for v, want := range map[string]bool{
		"10.0.0.0/8": true, "10.20.0.0/16": true, "172.0.0.0/8": true, "192.168.1.0/24": true, "100.64.0.0/10": true,
		"169.254.0.0/16": true, "0.0.0.0/8": true, "224.0.0.0/3": true, "198.18.0.0/15": true, "::ffff:10.0.0.0/104": true,
		"fd00::/8": true, "fe80::/64": true, "::1/128": true,
		"8.0.0.0/8": false, "198.51.100.0/24": false, "203.0.113.9/32": false, "2001:db8::/32": false, "::ffff:8.8.8.0/120": false,
	} {
		if got := SpecialUse(netip.MustParsePrefix(v)); got != want {
			t.Errorf("SpecialUse(%s) = %v", v, got)
		}
	}
	for v, want := range map[string]bool{"10.1.2.3": true, "::ffff:192.168.0.1": true, "100.100.1.1": true, "203.0.113.9": false, "2001:db8::1": false} {
		if got := SpecialUseAddr(netip.MustParseAddr(v)); got != want {
			t.Errorf("SpecialUseAddr(%s) = %v", v, got)
		}
	}
	// 修复前已经导入的内网条目：构建时忽略，内网地址不再命中
	in := NewIntel([]Indicator{{Type: "cidr", Value: "10.0.0.0/8"}, {Type: "cidr", Value: "172.0.0.0/8"}, {Type: "ip", Value: "192.168.1.1"},
		{Type: "cidr", Value: "198.51.100.0/24"}})
	if in.Len() != 1 {
		t.Errorf("len = %d", in.Len())
	}
	for _, v := range []string{"10.1.2.3", "172.16.5.5", "192.168.1.1"} {
		if _, ok := in.MatchIP(netip.MustParseAddr(v)); ok {
			t.Errorf("internal address %s matched", v)
		}
	}
}

func dns(src, dst string, name string, resp bool, rcode string, at time.Time) Event {
	return Event{Type: "dns", SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst), QName: name, Response: resp, RCode: rcode, Time: at}
}

func flow(src, dst string, port int, start time.Time, bytes int64) Event {
	return Event{Type: "flow", SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst), DstPort: port, Proto: "TCP",
		FlowStart: start, Time: start.Add(time.Minute), BytesToServer: bytes}
}

func kinds(fs []Finding) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range fs {
		m[f.Kind] = append(m[f.Kind], f)
	}
	return m
}

func TestIntelHits(t *testing.T) {
	a := NewAnalyzer(DefaultConfig(), NewIntel([]Indicator{{Type: "domain", Value: "evil.com", Source: "abuse.ch", Severity: "high"},
		{Type: "ip", Value: "203.0.113.9", Source: "自定义", Severity: "medium"}}), time.UTC)
	var all []Finding
	all = append(all, a.Observe(dns("10.0.0.5", "10.0.0.53", "cdn.evil.com", false, "", t0))...)
	all = append(all, a.Observe(dns("10.0.0.5", "10.0.0.53", "cdn.evil.com", false, "", t0.Add(time.Minute)))...) // 冷却期内不重复
	all = append(all, a.Observe(dns("10.0.0.53", "10.0.0.5", "cdn.evil.com", true, "NOERROR", t0))...)            // 应答不计
	all = append(all, a.Observe(Event{Type: "tls", SrcIP: netip.MustParseAddr("10.0.0.6"), DstIP: netip.MustParseAddr("198.51.100.1"),
		Host: "x.evil.com", Time: t0})...)
	all = append(all, a.Observe(flow("10.0.0.7", "203.0.113.9", 443, t0, 100))...)
	all = append(all, a.Observe(flow("203.0.113.9", "10.0.0.8", 22, t0, 100))...) // 入站
	all = append(all, a.Observe(flow("10.0.0.7", "10.0.0.9", 443, t0, 100))...)   // 内网之间
	if len(all) != 4 {
		t.Fatalf("intel findings: %+v", all)
	}
	if all[0].SrcIP != "10.0.0.5" || all[0].Severity != "high" || !strings.Contains(all[0].Detail, "abuse.ch") {
		t.Errorf("dns hit: %+v", all[0])
	}
	if all[2].Severity != "medium" || all[2].Peer != "203.0.113.9:443" || !strings.Contains(all[3].Detail, "被情报中的地址访问") || all[3].SrcIP != "10.0.0.8" {
		t.Errorf("flow hits: %+v %+v", all[2], all[3])
	}
}

func TestDGA(t *testing.T) {
	for name, want := range map[string]bool{"xjw3k9qzr7tpl.com": true, "qwrtzpklmnvbx.net": true, "google.com": false,
		"microsoftonline.com": false, "d1a2b3c4.cloudfront.net": false, "internationalization.org": false} {
		if DGALike(name) != want {
			t.Errorf("DGALike(%s) = %v", name, !want)
		}
	}
	a := NewAnalyzer(DefaultConfig(), nil, time.UTC)
	r := rand.New(rand.NewSource(1))
	// 单个域名的判定由上面的表格测试；这里只测窗口计数，生成器只产出判定为随机外观的名字
	randName := func() string {
		for {
			b := make([]byte, 14)
			for i := range b {
				b[i] = "bcdfghjklmnpqrstvwxz0123456789"[r.Intn(30)]
			}
			if n := string(b) + ".com"; DGALike(n) {
				return n
			}
		}
	}
	// 9 个不足阈值；能正常解析的随机外观域名（CDN）不计入
	for i := 0; i < 9; i++ {
		a.Observe(dns("10.0.0.53", "10.0.0.5", randName(), true, "NXDOMAIN", t0))
		a.Observe(dns("10.0.0.53", "10.0.0.5", randName(), true, "NOERROR", t0))
	}
	if f := kinds(a.Tick(t0.Add(time.Minute)))["dga"]; len(f) != 0 {
		t.Fatalf("dga fired below threshold: %+v", f)
	}
	a.Observe(dns("10.0.0.53", "10.0.0.5", randName(), true, "NXDOMAIN", t0.Add(2*time.Minute)))
	f := kinds(a.Tick(t0.Add(3 * time.Minute)))["dga"]
	if len(f) != 1 || f[0].SrcIP != "10.0.0.5" {
		t.Fatalf("dga: %+v", f)
	}
	if f := kinds(a.Tick(t0.Add(4 * time.Minute)))["dga"]; len(f) != 0 {
		t.Error("dga repeated within quiet period")
	}
}

func TestDNSTunnel(t *testing.T) {
	a := NewAnalyzer(DefaultConfig(), nil, time.UTC)
	for i := 0; i < 60; i++ {
		// iodine / dnscat2 风格：长的编码子域名
		a.Observe(dns("10.0.0.5", "10.0.0.53", fmt.Sprintf("%040x.t.tunnel-example.com", i*7919+1), false, "", t0.Add(time.Duration(i)*time.Second)))
		// 正常：大量短子域名、允许列表中的反向解析
		a.Observe(dns("10.0.0.6", "10.0.0.53", fmt.Sprintf("img%d.cdn-example.com", i), false, "", t0))
		a.Observe(dns("10.0.0.6", "10.0.0.53", fmt.Sprintf("%d.%d.0.10.in-addr.arpa", i, i), false, "", t0))
	}
	f := kinds(a.Tick(t0.Add(2 * time.Minute)))["dns_tunnel"]
	if len(f) != 1 || f[0].SrcIP != "10.0.0.5" || f[0].Peer != "tunnel-example.com" {
		t.Fatalf("dns tunnel: %+v", f)
	}
}

func TestBeacon(t *testing.T) {
	a := NewAnalyzer(DefaultConfig(), NewIntel([]Indicator{{Type: "ip", Value: "203.0.113.50", Source: "feodo"}}), time.UTC)
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 20; i++ {
		jitter := time.Duration(r.Intn(3000)-1500) * time.Millisecond // ±1.5 秒
		a.Observe(flow("10.0.0.5", "203.0.113.50", 443, t0.Add(time.Duration(i)*60*time.Second+jitter), 300))
		// 不规则的访问：浏览网页
		a.Observe(flow("10.0.0.6", "198.51.100.7", 443, t0.Add(time.Duration(r.Intn(3600))*time.Second), 300))
		// NTP 周期性但排除
		a.Observe(flow("10.0.0.7", "198.51.100.8", 123, t0.Add(time.Duration(i)*64*time.Second), 90))
	}
	f := kinds(a.Tick(t0.Add(25 * time.Minute)))["beacon"]
	if len(f) != 1 || f[0].SrcIP != "10.0.0.5" || f[0].Severity != "high" || !strings.Contains(f[0].Detail, "每隔约 1m0s") {
		t.Fatalf("beacon: %+v", f)
	}
}

func TestExfil(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ExfilBytes = 500 << 20
	a := NewAnalyzer(cfg, nil, time.UTC)
	night := time.Date(2026, 11, 1, 2, 10, 0, 0, time.UTC)
	day := time.Date(2026, 11, 1, 14, 10, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		a.Observe(flow("10.0.0.5", "203.0.113.20", 443, night.Add(time.Duration(i)*time.Minute), 100<<20))
		a.Observe(flow("10.0.0.6", "203.0.113.20", 443, day.Add(time.Duration(i)*time.Minute), 200<<20)) // 工作时间不计
	}
	f := kinds(a.Tick(night.Add(30 * time.Minute)))["exfil"]
	if len(f) != 1 || f[0].SrcIP != "10.0.0.5" || !strings.Contains(f[0].Detail, "600.0 MB") {
		t.Fatalf("exfil: %+v", f)
	}
}
