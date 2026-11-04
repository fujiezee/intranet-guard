package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// netbiosPort 是 NetBIOS 名称服务端口，测试中替换为本地端口。
var netbiosPort = 137

var errNoNetBIOSName = errors.New("no netbios workstation name")

// netbiosName 向 UDP 137 发送节点状态查询（NBSTAT，与 nbtscan、nbtstat -A 相同），返回对方的计算机名。
// 不需要账号，也不依赖路由器的 DNS；Windows 和开启了 Samba 的设备会应答。
func netbiosName(ctx context.Context, ip netip.Addr, timeout time.Duration) (string, error) {
	if !ip.Is4() {
		return "", errNoNetBIOSName // NetBIOS 只用于 IPv4
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip.String(), strconv.Itoa(netbiosPort)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	id := uint16(rand.Uint32())
	if _, err := conn.Write(nbstatQuery(id)); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf) // 端口不可达时这里会立即返回错误，不必等超时
		if err != nil {
			return "", err
		}
		if name, ok := parseNBStat(buf[:n], id); ok {
			return name, nil
		}
	}
}

// nbstatQuery 构造查询通配名 "*" 的 NBSTAT 请求（RFC 1002 4.2.17）。
func nbstatQuery(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // flags = 0, QDCOUNT = 1
	b = append(b, 32)                           // 编码后的名称长度
	name := [16]byte{'*'}                       // "*" 后补 15 个 0x00
	for _, c := range name {
		b = append(b, 'A'+(c>>4), 'A'+(c&0x0f)) // 一级编码：每个半字节加 'A'
	}
	b = append(b, 0)
	return append(b, 0x00, 0x21, 0x00, 0x01) // QTYPE = NBSTAT，QCLASS = IN
}

// parseNBStat 从 NBSTAT 应答中取出工作站名：后缀 0x00 的唯一名（不是组名，组名是工作组 / 域）。
func parseNBStat(b []byte, id uint16) (string, bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 || binary.BigEndian.Uint16(b[6:]) == 0 {
		return "", false // 不是对本次查询的应答，或没有回答记录
	}
	off := 12
	if off < len(b) && b[off]&0xc0 == 0xc0 {
		off += 2 // 压缩指针
	} else {
		for off < len(b) && b[off] != 0 {
			off += 1 + int(b[off])
		}
		off++ // 结尾的 0
	}
	if off+10 > len(b) || binary.BigEndian.Uint16(b[off:]) != 0x0021 {
		return "", false
	}
	rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
	rdata := b[off+10:]
	if rdlen < len(rdata) {
		rdata = rdata[:rdlen]
	}
	if len(rdata) < 1 {
		return "", false
	}
	for i, n := 0, int(rdata[0]); i < n; i++ {
		e := 1 + i*18 // 每项：15 字节名称、1 字节后缀、2 字节标志
		if e+18 > len(rdata) {
			break
		}
		suffix, group := rdata[e+15], rdata[e+16]&0x80 != 0
		if suffix != 0x00 || group {
			continue
		}
		if name := decodeNetBIOSName(rdata[e : e+15]); name != "" {
			return name, true
		}
	}
	return "", false
}

// decodeNetBIOSName 去掉补位空格；非 ASCII 的名称按 GBK 解码（中文 Windows 的 OEM 代码页）。
func decodeNetBIOSName(raw []byte) string {
	raw = []byte(strings.TrimRight(string(raw), " \x00"))
	s := string(raw)
	for _, c := range raw {
		if c >= 0x80 {
			if d, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
				s = string(d)
			}
			break
		}
	}
	if !utf8.ValidString(s) {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ""
		}
	}
	return s
}
