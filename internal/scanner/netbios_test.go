package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type nbEntry struct {
	name   []byte
	suffix byte
	group  bool
}

// nbstatResponse 构造 NBSTAT 应答；pointer 为 true 时回答记录的名称用压缩指针。
func nbstatResponse(id uint16, pointer bool, entries ...nbEntry) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0) // 应答、权威；ANCOUNT = 1
	if pointer {
		b = append(b, 0xc0, 0x0c)
	} else {
		b = append(b, nbstatQuery(id)[12:46]...) // 与查询相同的编码名
	}
	rdata := []byte{byte(len(entries))}
	for _, e := range entries {
		name := bytes.Repeat([]byte(" "), 15)
		copy(name, e.name)
		flags := byte(0x04) // 活动
		if e.group {
			flags |= 0x80
		}
		rdata = append(rdata, name...)
		rdata = append(rdata, e.suffix, flags, 0x00)
	}
	rdata = append(rdata, make([]byte, 46)...) // 网卡地址与统计信息
	b = append(b, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func TestNBStatQuery(t *testing.T) {
	q := nbstatQuery(0x1234)
	if len(q) != 50 || q[0] != 0x12 || q[1] != 0x34 || q[5] != 1 || q[12] != 32 {
		t.Fatalf("header: % x", q[:13])
	}
	if want := "CK" + string(bytes.Repeat([]byte("A"), 30)); string(q[13:45]) != want {
		t.Errorf("encoded name = %q", q[13:45])
	}
	if !bytes.Equal(q[45:], []byte{0, 0x00, 0x21, 0x00, 0x01}) {
		t.Errorf("tail = % x", q[45:])
	}
}

func TestParseNBStat(t *testing.T) {
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("财务电脑"))
	if err != nil {
		t.Fatal(err)
	}
	workstation := []nbEntry{
		{[]byte("WORKGROUP"), 0x00, true}, // 组名（工作组）排在前面也要跳过
		{[]byte("DESKTOP-AB12CD"), 0x20, false},
		{[]byte("DESKTOP-AB12CD"), 0x00, false},
	}
	for _, c := range []struct {
		name   string
		resp   []byte
		id     uint16
		want   string
		wantOK bool
	}{
		{"workstation", nbstatResponse(7, false, workstation...), 7, "DESKTOP-AB12CD", true},
		{"compressed name", nbstatResponse(7, true, workstation...), 7, "DESKTOP-AB12CD", true},
		{"GBK name", nbstatResponse(7, false, nbEntry{gbk, 0x00, false}), 7, "财务电脑", true},
		{"other query", nbstatResponse(8, false, workstation...), 7, "", false},
		{"only group names", nbstatResponse(7, false, nbEntry{[]byte("WORKGROUP"), 0x00, true}), 7, "", false},
		{"no entries", nbstatResponse(7, false), 7, "", false},
		{"control characters", nbstatResponse(7, false, nbEntry{[]byte("BAD\x01NAME"), 0x00, false}), 7, "", false},
	} {
		got, ok := parseNBStat(c.resp, c.id)
		if got != c.want || ok != c.wantOK {
			t.Errorf("%s: parseNBStat = %q, %v; want %q, %v", c.name, got, ok, c.want, c.wantOK)
		}
	}

	// 截断或畸形的应答不能越界
	full := nbstatResponse(7, false, workstation...)
	for n := range full {
		if name, ok := parseNBStat(full[:n], 7); ok && n < len(full)-46 {
			t.Errorf("truncated to %d bytes: got %q", n, name)
		}
	}
	bad := append([]byte(nil), full...)
	bad[12] = 0x3f // 名称长度超出报文
	parseNBStat(bad, 7)
}

// 对本地模拟的 NetBIOS 应答方查询：应答 ID 必须与查询一致。
func TestNetBIOSName(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			id := binary.BigEndian.Uint16(buf)
			pc.WriteTo(nbstatResponse(id+1, false, nbEntry{[]byte("STALE"), 0x00, false}), from) // 无关应答应被忽略
			pc.WriteTo(nbstatResponse(id, false, nbEntry{[]byte("PRINTER-3F"), 0x00, false}), from)
		}
	}()
	old := netbiosPort
	netbiosPort = pc.LocalAddr().(*net.UDPAddr).Port
	t.Cleanup(func() { netbiosPort = old })

	name, err := netbiosName(context.Background(), netip.MustParseAddr("127.0.0.1"), time.Second)
	if err != nil || name != "PRINTER-3F" {
		t.Fatalf("netbiosName = %q, %v", name, err)
	}
	if _, err := netbiosName(context.Background(), netip.MustParseAddr("::1"), time.Second); err == nil {
		t.Error("IPv6 should not be queried")
	}
}
