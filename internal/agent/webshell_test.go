package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe/internal/model"
)

func TestWebshellScan(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "app", "upload"), 0o755)
	os.WriteFile(filepath.Join(root, "app", "index.php"), []byte("<?php echo 'hello'; ?>"), 0o644)
	os.WriteFile(filepath.Join(root, "app", "style.css"), []byte("body{}"), 0o644)

	base := scanWebDirs([]string{root, "/does/not/exist"})
	if len(base) != 1 {
		t.Fatalf("baseline = %v (only scripts are tracked)", base)
	}

	time.Sleep(10 * time.Millisecond)
	shell := filepath.Join(root, "app", "upload", "x.php")
	os.WriteFile(shell, []byte(`<?php @eval(base64_decode($_POST['c'])); ?>`), 0o644)
	plain := filepath.Join(root, "app", "upload", "about.jsp")
	os.WriteFile(plain, []byte(`<%= "about" %>`), 0o644)
	os.WriteFile(filepath.Join(root, "app", "index.php"), []byte("<?php echo 'hello world'; ?>"), 0o644)

	events := diffWebFiles(base, scanWebDirs([]string{root}), time.Now())
	got := map[string]model.HostEvent{}
	for _, e := range events {
		got[filepath.Base(e.Path)] = e
	}
	if e := got["x.php"]; e.Severity != "high" || !strings.Contains(e.Detail, "eval") || !strings.Contains(e.Detail, "编码混淆") {
		t.Errorf("webshell: %+v", e)
	}
	if e := got["about.jsp"]; e.Severity != "medium" || !strings.HasPrefix(e.Detail, "新增") {
		t.Errorf("plain new script: %+v", e)
	}
	if e := got["index.php"]; !strings.HasPrefix(e.Detail, "脚本文件被修改") {
		t.Errorf("modified: %+v", e)
	}
	if len(events) != 3 {
		t.Errorf("events = %d", len(events))
	}
}

func TestWebshellSimulation(t *testing.T) {
	dir := t.TempDir()
	simDuration = 300 * time.Millisecond
	t.Cleanup(func() { simDuration = 120 * time.Second })

	a := &Agent{cfg: Config{WebDirs: []string{"/does/not/exist", dir}}}
	res := a.runCommand(model.AgentCommand{ID: "sim-00001111", Type: "simulate", Scenario: "webshell"})
	path := filepath.Join(dir, "safe-sim-sim-00001111.php")
	b, err := os.ReadFile(path)
	if res.Status != "done" || err != nil || webshellFeaturesOf(path) != nil {
		t.Fatalf("webshell sim: %+v %v features=%v content=%q", res, err, webshellFeaturesOf(path), b)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("simulation file not removed")
	}

	a.cfg.WebDirs = []string{"/does/not/exist"}
	if res := a.runCommand(model.AgentCommand{ID: "sim-00001112", Type: "simulate", Scenario: "webshell"}); res.Status != "not_applicable" {
		t.Errorf("no web dir: %+v", res)
	}
	// 没有命令审计能力时，命令类自检如实报告不适用。
	for _, sc := range []string{"reverse_shell", "download_exec"} {
		if res := a.runCommand(model.AgentCommand{ID: "sim-00001113", Type: "simulate", Scenario: sc}); res.Status != "not_applicable" {
			t.Errorf("%s without exec monitor: %+v", sc, res)
		}
	}
}
