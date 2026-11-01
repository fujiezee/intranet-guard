//go:build !windows

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safe/internal/model"
)

// fakeVersion 构造一个"新版本"：用 shell 脚本模拟自检输出。
func fakeVersion(selfTest string) []byte {
	return []byte("#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -self-test ] && { " + selfTest + "; }; done\nexit 0\n")
}

func TestRunUpgrade(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin", "safe-agent")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("OLD"), 0o755)
	executable = func() (string, error) { return exe, nil }
	t.Cleanup(func() { executable = os.Executable })

	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/download/safe-agent-linux-amd64" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	a := &Agent{cfg: Config{ServerURL: srv.URL, StatePath: filepath.Join(dir, "state.json"), HTTP: srv.Client()}}
	cmd := func(id, ver string, b []byte) model.AgentCommand {
		sum := sha256.Sum256(b)
		return model.AgentCommand{ID: id, Type: "upgrade", Params: map[string]string{
			"version": ver, "file": "safe-agent-linux-amd64", "sha256": hex.EncodeToString(sum[:])}}
	}
	old := func() bool { b, _ := os.ReadFile(exe); return string(b) == "OLD" }

	// 校验失败：不替换
	body = fakeVersion(`echo "version=9.9.9 id=x ok"; exit 0`)
	bad := cmd("upg-00000001", "9.9.9", body)
	bad.Params["sha256"] = strings.Repeat("0", 64)
	if r := a.runUpgrade(bad); r.Status != "error" || !strings.Contains(r.Detail, "SHA-256") || !old() {
		t.Errorf("checksum mismatch: %+v", r)
	}
	// 自检失败（例如无法通过管理中心认证）：不替换
	body = fakeVersion(`echo "self-test failed: management server rejected this node"; exit 1`)
	if r := a.runUpgrade(cmd("upg-00000002", "9.9.9", body)); r.Status != "error" || !strings.Contains(r.Detail, "自检失败") || !old() {
		t.Errorf("self-test failure: %+v", r)
	}
	// 版本号与预期不符（管理中心提供的程序与清单不一致）：不替换
	body = fakeVersion(`echo "version=1.0.0 id=x ok"; exit 0`)
	if r := a.runUpgrade(cmd("upg-00000003", "9.9.9", body)); r.Status != "error" || !strings.Contains(r.Detail, "版本号") || !old() {
		t.Errorf("version mismatch: %+v", r)
	}
	if a.restartRequested {
		t.Fatal("restart requested after failed upgrades")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", ".safe-agent-upgrade")); !os.IsNotExist(err) {
		t.Error("downloaded file left behind after failure")
	}

	// 成功：新程序就位，旧程序保留为 .prev，记录待确认，要求重启
	body = fakeVersion(`echo "version=9.9.9 id=x ok"; exit 0`)
	r := a.runUpgrade(cmd("upg-00000004", "9.9.9", body))
	if r.Status != "done" || !a.restartRequested {
		t.Fatalf("upgrade: %+v", r)
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "OLD" {
		t.Error(".prev does not hold the old binary")
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "version=9.9.9") {
		t.Error("new binary not in place")
	}
	u, ok := readUpgradeFile(filepath.Join(dir, "upgrade-pending"))
	realExe, _ := filepath.EvalSymlinks(exe) // macOS 的临时目录在符号链接下
	if !ok || u.attempt != "upg-00000004" || u.to != "9.9.9" || u.exe != realExe {
		t.Errorf("pending: %+v %v", u, ok)
	}

	// 新版本首次上报成功后确认：删除 .prev 和待确认记录
	saved := Version
	Version = "9.9.9"
	t.Cleanup(func() { Version = saved })
	b := &Agent{cfg: a.cfg}
	b.loadUpgradeState()
	b.commitUpgrade()
	if _, err := os.Stat(exe + ".prev"); !os.IsNotExist(err) {
		t.Error(".prev not removed after commit")
	}
	if _, err := os.Stat(filepath.Join(dir, "upgrade-pending")); !os.IsNotExist(err) {
		t.Error("upgrade-pending not removed after commit")
	}

	// 回退后旧版本启动：向管理中心报告失败
	os.WriteFile(filepath.Join(dir, "upgrade-rolledback"), []byte("4\nupg-00000005\n0.9.0\n9.9.9\n"+exe+"\n"), 0o600)
	c := &Agent{cfg: a.cfg}
	c.loadUpgradeState()
	if len(c.results) != 1 || c.results[0].ID != "upg-00000005" || c.results[0].Status != "error" || !strings.Contains(c.results[0].Detail, "自动回退") {
		t.Errorf("rollback report: %+v", c.results)
	}

	// 无效指令一律拒绝
	for _, p := range []map[string]string{
		{"version": "1", "file": "../../etc/passwd", "sha256": strings.Repeat("a", 64)},
		{"version": "1", "file": "safe-agent-linux-amd64", "sha256": "abc"},
	} {
		if r := a.runUpgrade(model.AgentCommand{ID: "upg-00000006", Type: "upgrade", Params: p}); r.Status != "error" {
			t.Errorf("invalid command accepted: %+v", p)
		}
	}
}
