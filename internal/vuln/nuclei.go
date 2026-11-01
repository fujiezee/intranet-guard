package vuln

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"safe/internal/model"
)

// NucleiPrefix 是 Nuclei 发现的 check_id 前缀。
const NucleiPrefix = "nuclei:"

// nucleiArgs 只运行非破坏性的模板：排除拒绝服务、模糊测试和登录尝试，不连接公网回连服务，限制发包速度。
var nucleiArgs = []string{"-jsonl", "-silent", "-disable-update-check", "-no-interactsh",
	"-severity", "critical,high,medium", "-exclude-tags", "dos,fuzz,intrusive,bruteforce,default-login", "-rate-limit", "50"}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	IP        string `json:"ip"`
	Port      string `json:"port"`
	MatchedAt string `json:"matched-at"`
}

// RunNuclei 用探针上安装的 nuclei 检查已发现的开放端口。只接受这次扫描到的主机的结果。
func RunNuclei(ctx context.Context, assets []model.Asset) ([]model.CheckResult, error) {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return nil, errors.New("nuclei is not installed on this probe")
	}
	var list strings.Builder
	known := map[string]bool{}
	for _, a := range assets {
		known[a.IP] = true
		for _, p := range a.Ports {
			fmt.Fprintln(&list, net.JoinHostPort(a.IP, strconv.Itoa(p.Port)))
		}
	}
	if list.Len() == 0 {
		return nil, nil
	}
	f, err := os.CreateTemp("", "safe-nuclei-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(list.String())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, append([]string{"-list", f.Name()}, nucleiArgs...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	results := parseNuclei(stdout.Bytes(), known)
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return results, fmt.Errorf("nuclei: %w: %s", runErr, msg)
	}
	return results, nil
}

func parseNuclei(out []byte, known map[string]bool) []model.CheckResult {
	seen := map[string]bool{}
	var results []model.CheckResult
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20) // 每行带完整请求和响应
	for sc.Scan() {
		var r nucleiResult
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.TemplateID == "" || !known[r.IP] {
			continue
		}
		port := nucleiPort(r)
		key := r.IP + "/" + strconv.Itoa(port) + "/" + r.TemplateID
		if seen[key] {
			continue
		}
		seen[key] = true
		sev := model.SeverityMedium
		if r.Info.Severity == "critical" || r.Info.Severity == "high" {
			sev = model.SeverityHigh
		}
		results = append(results, model.CheckResult{IP: r.IP, Port: port, CheckID: NucleiPrefix + r.TemplateID, Vulnerable: true,
			Title: r.Info.Name, Severity: sev, Detail: "Nuclei " + r.TemplateID + "：" + r.MatchedAt})
	}
	return results
}

func nucleiPort(r nucleiResult) int {
	if p, err := strconv.Atoi(r.Port); err == nil {
		return p
	}
	if u, err := url.Parse(r.MatchedAt); err == nil && u.Port() != "" {
		p, _ := strconv.Atoi(u.Port())
		return p
	}
	if _, p, err := net.SplitHostPort(r.MatchedAt); err == nil {
		n, _ := strconv.Atoi(p)
		return n
	}
	return 0
}
