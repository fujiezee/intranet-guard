package vuln

import (
	"regexp"
	"strconv"

	"safe/internal/model"
)

// BannerRule 根据服务 Banner 中的版本号判断已知漏洞。只收录影响范围明确、Banner 能可靠识别的漏洞。
type BannerRule struct {
	ID       string
	Title    string
	Severity model.Severity
	// Applies 判断该 Banner 是否属于规则对应的软件；属于时 Vulnerable 的结论（含"不受影响"）才有意义。
	Applies    *regexp.Regexp
	Vulnerable func(m []string) bool
	Detail     string
}

var reOpenSSH = regexp.MustCompile(`^SSH-2\.0-OpenSSH_(\d+)\.(\d+)(?:p(\d+))?`)

// sshVersion 把 OpenSSH 版本编码为可比较的整数：9.8p1 → 90801。
func sshVersion(m []string) int {
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return major*10000 + minor*100 + patch
}

var BannerRules = []BannerRule{
	{
		ID:       "CVE-2024-6387",
		Title:    "OpenSSH regreSSHion 远程代码执行（CVE-2024-6387）",
		Severity: model.SeverityMedium, // 发行版常回移植补丁而不改版本号，需人工核实
		Applies:  reOpenSSH,
		Vulnerable: func(m []string) bool {
			v := sshVersion(m)
			return v >= 80501 && v < 90801
		},
		Detail: "OpenSSH 8.5p1 ~ 9.7p1 的 sshd 存在信号处理竞争条件，可导致未认证远程代码执行。" +
			"注意：Ubuntu / Debian / RHEL 等发行版可能已回移植补丁而版本号不变，请对照发行版安全公告核实。",
	},
	{
		ID:         "CVE-2011-2523",
		Title:      "vsftpd 2.3.4 后门（CVE-2011-2523）",
		Severity:   model.SeverityHigh,
		Applies:    regexp.MustCompile(`vsFTPd ([\d.]+)`),
		Vulnerable: func(m []string) bool { return m[1] == "2.3.4" },
		Detail:     "该版本的官方源码包曾被植入后门：用户名以 :) 结尾即可在 6200 端口获得 root shell。",
	},
	{
		ID:         "CVE-2015-3306",
		Title:      "ProFTPD 1.3.5 mod_copy 任意文件复制（CVE-2015-3306）",
		Severity:   model.SeverityHigh,
		Applies:    regexp.MustCompile(`ProFTPD ([\d.]+[a-z]?)`),
		Vulnerable: func(m []string) bool { return m[1] == "1.3.5" },
		Detail:     "未认证用户可通过 SITE CPFR/CPTO 复制任意文件，常被用于写入 Web 目录获取权限。",
	},
}

// CheckBanners 对扫描结果中的每个 Banner 执行版本规则，返回适用规则的结论（包括"不受影响"）。
func CheckBanners(assets []model.Asset) []model.CheckResult {
	var out []model.CheckResult
	for _, a := range assets {
		for _, p := range a.Ports {
			if p.Banner == "" {
				continue
			}
			for _, r := range BannerRules {
				m := r.Applies.FindStringSubmatch(p.Banner)
				if m == nil {
					continue
				}
				res := model.CheckResult{IP: a.IP, Port: p.Port, CheckID: r.ID}
				if r.Vulnerable(m) {
					res.Vulnerable, res.Title, res.Severity = true, r.Title, r.Severity
					res.Detail = r.Detail + " Banner：" + p.Banner
				}
				out = append(out, res)
			}
		}
	}
	return out
}
