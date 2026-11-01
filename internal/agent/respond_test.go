package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
)

func TestIsolationRuleset(t *testing.T) {
	rs := isolationRuleset([]netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.53"), netip.MustParseAddr("fd00::1")})
	for _, want := range []string{
		"policy drop", `iif "lo" accept`, "ip saddr { 10.0.0.5, 10.0.0.53 } accept", "ip daddr { 10.0.0.5, 10.0.0.53 } accept",
		"ip6 saddr { fd00::1 } accept", "chain forward",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
	// 没有 IPv6 地址时不能出现空集合（nft 语法错误）
	if rs := isolationRuleset([]netip.Addr{netip.MustParseAddr("10.0.0.5")}); strings.Contains(rs, "ip6") {
		t.Errorf("empty ip6 set rendered:\n%s", rs)
	}
}

func TestQuarantineAndRestore(t *testing.T) {
	state := t.TempDir()
	a := &Agent{cfg: Config{StatePath: filepath.Join(state, "state.json")}}
	web := t.TempDir()
	evil := filepath.Join(web, "evil.php")
	os.WriteFile(evil, []byte("<?php eval($_POST[1]); ?>"), 0o640)

	detail, err := a.quarantine("act-0000aaaa", evil)
	if err != nil || !strings.Contains(detail, "SHA-256") {
		t.Fatalf("quarantine: %q %v", detail, err)
	}
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Fatal("file still at original location")
	}
	// Windows 没有 Unix 权限位，访问控制由状态目录的 ACL 保证
	unixPerm := runtime.GOOS != "windows"
	if fi, err := os.Stat(filepath.Join(state, "quarantine", "act-0000aaaa", "file")); err != nil || (unixPerm && fi.Mode().Perm() != 0o600) {
		t.Fatalf("quarantined copy: %v %v", fi, err)
	}
	if _, err := a.restoreFile("act-0000aaaa"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(evil); err != nil || (unixPerm && fi.Mode().Perm() != 0o640) {
		t.Errorf("restored file: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(state, "quarantine", "act-0000aaaa")); !os.IsNotExist(err) {
		t.Error("quarantine dir not cleaned after restore")
	}

	for _, bad := range []string{"/etc/passwd", "/usr/bin/ls", "relative/x.php", filepath.Join(state, "state.json"), web} {
		if _, err := a.quarantine("act-0000aaab", bad); err == nil {
			t.Errorf("quarantine(%q) allowed", bad)
		}
	}
	if _, err := a.restoreFile("../../etc"); err == nil {
		t.Error("restore with traversal id allowed")
	}
}

func TestActionValidation(t *testing.T) {
	a := &Agent{cfg: Config{StatePath: filepath.Join(t.TempDir(), "s.json")}}
	expired := model.AgentCommand{ID: "act-0000cccc", Type: "action", Action: model.ActBlockIP,
		Params: map[string]string{"ip": "10.6.6.6", "duration": "600"}, ExpiresAt: time.Now().Add(-time.Minute)}
	if res := a.runCommand(expired); res.Status != "error" || !strings.Contains(res.Detail, "过期") {
		t.Errorf("expired action: %+v", res)
	}
	if res := a.runCommand(model.AgentCommand{ID: "../x", Type: "action", Action: model.ActRelease}); res.Status != "error" {
		t.Errorf("bad id accepted: %+v", res)
	}
	for _, p := range []map[string]string{{"ip": "not-an-ip", "duration": "600"}, {"ip": "10.0.0.1", "duration": "5"}} {
		if _, err := blockIP(p["ip"], p["duration"]); err == nil {
			t.Errorf("blockIP(%v) accepted", p)
		}
	}
	if _, err := killProcess("1", "/sbin/init"); err == nil {
		t.Error("kill pid 1 allowed")
	}
	if _, err := killProcess("12345", ""); err == nil {
		t.Error("kill without exe allowed")
	}
}
