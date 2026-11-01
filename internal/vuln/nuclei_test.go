package vuln

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safe/internal/model"
)

func TestParseNuclei(t *testing.T) {
	out := `{"template-id":"exposed-panel","info":{"name":"Panel","severity":"critical"},"ip":"10.0.0.5","port":"8080","matched-at":"http://10.0.0.5:8080/admin"}
{"template-id":"exposed-panel","info":{"name":"Panel","severity":"critical"},"ip":"10.0.0.5","port":"8080","matched-at":"http://10.0.0.5:8080/other"}
{"template-id":"no-port","info":{"name":"N","severity":"medium"},"ip":"10.0.0.5","matched-at":"https://10.0.0.5:8443/"}
{"template-id":"elsewhere","info":{"name":"X","severity":"high"},"ip":"203.0.113.9","port":"80","matched-at":"http://203.0.113.9/"}
not json
`
	got := parseNuclei([]byte(out), map[string]bool{"10.0.0.5": true})
	if len(got) != 2 {
		t.Fatalf("results: %+v", got)
	}
	if r := got[0]; r.CheckID != "nuclei:exposed-panel" || r.Port != 8080 || r.Severity != model.SeverityHigh || !r.Vulnerable {
		t.Errorf("first: %+v", r)
	}
	if r := got[1]; r.Port != 8443 || r.Severity != model.SeverityMedium {
		t.Errorf("second: %+v", r)
	}
}

func TestRunNuclei(t *testing.T) {
	assets := []model.Asset{{IP: "10.0.0.5", Ports: []model.Port{{Port: 80}}}}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if _, err := RunNuclei(context.Background(), assets); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("missing binary: %v", err)
	}
	// 假程序：记录参数，退出码由环境决定
	script := "#!/bin/sh\n/bin/echo \"$@\" > " + dir + "/args\n/bin/cat \"$2\" > " + dir + "/list\n" +
		"/bin/echo '{\"template-id\":\"t\",\"info\":{\"name\":\"T\",\"severity\":\"high\"},\"ip\":\"10.0.0.5\",\"port\":\"80\"}'\nexit $NUCLEI_EXIT\n"
	if err := os.WriteFile(filepath.Join(dir, "nuclei"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_EXIT", "0")
	got, err := RunNuclei(context.Background(), assets)
	if err != nil || len(got) != 1 {
		t.Fatalf("run: %v %+v", err, got)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, want := range []string{"-no-interactsh", "dos,fuzz,intrusive", "-rate-limit 50"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("safety flag %q missing: %s", want, args)
		}
	}
	if list, _ := os.ReadFile(filepath.Join(dir, "list")); strings.TrimSpace(string(list)) != "10.0.0.5:80" {
		t.Errorf("target list: %q", list)
	}
	t.Setenv("NUCLEI_EXIT", "1")
	if got, err := RunNuclei(context.Background(), assets); err == nil || len(got) != 1 {
		t.Errorf("failed run must report the error and keep findings: %v %+v", err, got)
	}
}
