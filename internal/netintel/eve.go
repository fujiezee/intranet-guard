// Package netintel 在探针本地分析 Suricata 的 dns / tls / http / flow 记录：威胁情报命中、DGA、DNS 隧道、
// C2 心跳、非工作时间大流量外传。原始记录量很大，只上报分析结果。
package netintel

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

// Event 是从 eve.json 中取出的网络记录。
type Event struct {
	Time    time.Time
	Type    string // dns / tls / http / flow
	SrcIP   netip.Addr
	DstIP   netip.Addr
	DstPort int
	Proto   string

	// dns
	QName    string
	Response bool   // 应答记录（src 为 DNS 服务器，dst 为客户端）
	RCode    string // 应答码，如 NXDOMAIN
	// tls / http
	Host string
	// flow
	BytesToServer int64
	FlowStart     time.Time
}

type eveNet struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	DNS       *struct {
		Type    string `json:"type"` // v2: query / answer；v3: request / response
		RRName  string `json:"rrname"`
		RCode   string `json:"rcode"`
		Queries []struct {
			RRName string `json:"rrname"`
		} `json:"queries"`
	} `json:"dns"`
	TLS *struct {
		SNI string `json:"sni"`
	} `json:"tls"`
	HTTP *struct {
		Hostname string `json:"hostname"`
	} `json:"http"`
	Flow *struct {
		BytesToServer int64  `json:"bytes_toserver"`
		Start         string `json:"start"`
	} `json:"flow"`
}

// eveTime 解析 Suricata 的时间格式（2026-11-01T09:04:19.123456+0800）。
func eveTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.999999-0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ParseEve 解析一行 eve.json；不是 dns / tls / http / flow 记录时返回 false。
func ParseEve(line []byte) (Event, bool) {
	// 先用字符串判断类型，跳过占多数的其他记录，避免完整反序列化
	if !hasEventType(line) {
		return Event{}, false
	}
	var r eveNet
	if err := json.Unmarshal(line, &r); err != nil {
		return Event{}, false
	}
	src, err1 := netip.ParseAddr(r.SrcIP)
	dst, err2 := netip.ParseAddr(r.DestIP)
	if err1 != nil || err2 != nil {
		return Event{}, false
	}
	e := Event{Time: eveTime(r.Timestamp), Type: r.EventType, SrcIP: src.Unmap(), DstIP: dst.Unmap(), DstPort: r.DestPort, Proto: r.Proto}
	switch {
	case r.EventType == "dns" && r.DNS != nil:
		e.QName = r.DNS.RRName
		if e.QName == "" && len(r.DNS.Queries) > 0 {
			e.QName = r.DNS.Queries[0].RRName
		}
		e.QName = strings.ToLower(strings.TrimSuffix(e.QName, "."))
		e.Response = r.DNS.Type == "answer" || r.DNS.Type == "response"
		e.RCode = strings.ToUpper(r.DNS.RCode)
		if e.QName == "" {
			return Event{}, false
		}
	case r.EventType == "tls" && r.TLS != nil:
		e.Host = strings.ToLower(r.TLS.SNI)
	case r.EventType == "http" && r.HTTP != nil:
		e.Host = strings.ToLower(r.HTTP.Hostname)
	case r.EventType == "flow" && r.Flow != nil:
		e.BytesToServer = r.Flow.BytesToServer
		e.FlowStart = eveTime(r.Flow.Start)
	default:
		return Event{}, false
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	return e, true
}

func hasEventType(line []byte) bool {
	s := string(line)
	for _, t := range []string{`"event_type":"dns"`, `"event_type":"tls"`, `"event_type":"http"`, `"event_type":"flow"`} {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// Internal 判断是否为内网地址（RFC 1918、CGNAT、ULA、回环、链路本地）。
func Internal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
