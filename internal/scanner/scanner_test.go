package scanner

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestExpandTargets(t *testing.T) {
	tests := []struct {
		specs []string
		want  int
	}{
		{[]string{"10.0.0.1"}, 1},
		{[]string{"10.0.0.0/24"}, 254},
		{[]string{"10.0.0.0/31"}, 2},
		{[]string{"10.0.0.5-10"}, 6},
		{[]string{"10.0.0.1", "10.0.0.0/30"}, 2}, // 去重
		{[]string{"10.0.0.0/16"}, 65534},
	}
	for _, tt := range tests {
		got, err := ExpandTargets(tt.specs)
		if err != nil {
			t.Fatalf("ExpandTargets(%v): %v", tt.specs, err)
		}
		if len(got) != tt.want {
			t.Errorf("ExpandTargets(%v) = %d addrs, want %d", tt.specs, len(got), tt.want)
		}
	}

	for _, bad := range []string{"10.0.0.0/8", "10.0.0.300", "10.0.0.10-5", "::1", "foo"} {
		if _, err := ExpandTargets([]string{bad}); err == nil {
			t.Errorf("ExpandTargets(%q) should fail", bad)
		}
	}
}

func TestScanFindsOpenPortAndBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// 再拿一个空闲端口作为关闭端口，用来验证 RST 不会被报告为开放。
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	assets := Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Options{
		Ports:   []int{openPort, closedPort},
		Timeout: 500 * time.Millisecond,
	})
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	ports := assets[0].Ports
	if len(ports) != 1 || ports[0].Port != openPort {
		t.Fatalf("ports = %+v, want only %d", ports, openPort)
	}
	if ports[0].Service != "ssh" || ports[0].Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("service/banner = %q/%q", ports[0].Service, ports[0].Banner)
	}
}
