package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"safe/internal/model"
)

// 处置动作在主机上执行。只支持预定义的动作和经过校验的参数，不执行任意命令。
// 防火墙优先使用 nftables（独立的表，不改动系统已有规则），封禁 IP 在没有 nft 的老系统上回退到 iptables。

var reActionID = regexp.MustCompile(`^act-[0-9a-f]{8}$`)

func (a *Agent) runAction(cmd model.AgentCommand) model.CommandResult {
	res := model.CommandResult{ID: cmd.ID, Status: "done"}
	fail := func(err error) model.CommandResult {
		res.Status, res.Detail = "error", err.Error()
		slog.Warn("response action failed", "id", cmd.ID, "action", cmd.Action, "err", err)
		return res
	}
	if !reActionID.MatchString(cmd.ID) {
		return fail(errors.New("invalid action id"))
	}
	if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
		return fail(errors.New("处置指令已过期，未执行"))
	}
	if runtime.GOOS != "linux" {
		return fail(errors.New("处置动作仅支持 Linux"))
	}
	var detail string
	var err error
	p := cmd.Params
	switch cmd.Action {
	case model.ActBlockIP:
		// 封禁管理中心地址会让 Agent 失联、无法再接收解除指令
		if mgmt, merr := a.managementAddrs(); merr == nil {
			for _, m := range mgmt {
				if ip, perr := parseIP(p["ip"]); perr == nil && ip == m {
					return fail(errors.New("不能封禁管理中心地址"))
				}
			}
		}
		detail, err = blockIP(p["ip"], p["duration"])
	case model.ActUnblockIP:
		detail, err = unblockIP(p["ip"])
	case model.ActKillProcess:
		detail, err = killProcess(p["pid"], p["exe"])
	case model.ActQuarantine:
		detail, err = a.quarantine(cmd.ID, p["path"])
	case model.ActRestoreFile:
		detail, err = a.restoreFile(p["quarantine_id"])
	case model.ActIsolate:
		detail, err = a.isolate(p["allow"])
	case model.ActRelease:
		detail, err = release()
	default:
		err = fmt.Errorf("unknown action %q", cmd.Action)
	}
	if err != nil {
		return fail(err)
	}
	res.Detail = detail
	slog.Warn("response action executed", "id", cmd.ID, "action", cmd.Action, "detail", detail)
	return res
}

func runCmd(name string, stdin string, args ...string) error {
	c := exec.Command(name, args...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hasNft() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

func parseIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ip, fmt.Errorf("invalid ip %q", s)
	}
	return ip.Unmap(), nil
}

// --- 封禁 IP ---

const blockTable = `table inet safe_block {
	set v4 { type ipv4_addr; flags timeout; }
	set v6 { type ipv6_addr; flags timeout; }
	chain input { type filter hook input priority -5; policy accept; ip saddr @v4 drop; ip6 saddr @v6 drop; }
	chain output { type filter hook output priority -5; policy accept; ip daddr @v4 drop; ip6 daddr @v6 drop; }
}
`

func blockIP(ipStr, durStr string) (string, error) {
	ip, err := parseIP(ipStr)
	if err != nil {
		return "", err
	}
	secs, err := strconv.Atoi(durStr)
	if err != nil || secs < 60 {
		return "", fmt.Errorf("invalid duration %q", durStr)
	}
	if hasNft() {
		if runCmd("nft", "", "list", "table", "inet", "safe_block") != nil {
			if err := runCmd("nft", blockTable, "-f", "-"); err != nil {
				return "", err
			}
		}
		set := "v4"
		if ip.Is6() {
			set = "v6"
		}
		// 已在集合中时先删除，以新的时长重新加入
		_ = runCmd("nft", "", "delete", "element", "inet", "safe_block", set, "{ "+ip.String()+" }")
		if err := runCmd("nft", "", "add", "element", "inet", "safe_block", set,
			fmt.Sprintf("{ %s timeout %ds }", ip, secs)); err != nil {
			return "", err
		}
		return fmt.Sprintf("nftables 已封禁 %s（%d 秒后自动解除）", ip, secs), nil
	}
	// 老系统（如 CentOS 7）回退到 iptables；到期由 Agent 定时解除，Agent 重启会丢失定时，需手动解除
	ipt := "iptables"
	if ip.Is6() {
		ipt = "ip6tables"
	}
	for _, rule := range [][]string{{"INPUT", "-s"}, {"OUTPUT", "-d"}} {
		if err := runCmd(ipt, "", "-w", "-I", rule[0], rule[1], ip.String(), "-m", "comment", "--comment", "safe-block", "-j", "DROP"); err != nil {
			return "", err
		}
	}
	time.AfterFunc(time.Duration(secs)*time.Second, func() { _, _ = unblockIP(ip.String()) })
	return fmt.Sprintf("iptables 已封禁 %s（%d 秒后解除）", ip, secs), nil
}

func unblockIP(ipStr string) (string, error) {
	ip, err := parseIP(ipStr)
	if err != nil {
		return "", err
	}
	if hasNft() {
		set := "v4"
		if ip.Is6() {
			set = "v6"
		}
		if err := runCmd("nft", "", "delete", "element", "inet", "safe_block", set, "{ "+ip.String()+" }"); err != nil &&
			!strings.Contains(err.Error(), "No such file") {
			return "", err
		}
		return "已解除封禁 " + ip.String(), nil
	}
	ipt := "iptables"
	if ip.Is6() {
		ipt = "ip6tables"
	}
	for _, rule := range [][]string{{"INPUT", "-s"}, {"OUTPUT", "-d"}} {
		_ = runCmd(ipt, "", "-w", "-D", rule[0], rule[1], ip.String(), "-m", "comment", "--comment", "safe-block", "-j", "DROP")
	}
	return "已解除封禁 " + ip.String(), nil
}

// --- 结束进程 ---

func killProcess(pidStr, exe string) (string, error) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return "", fmt.Errorf("invalid pid %q", pidStr)
	}
	if exe == "" {
		return "", errors.New("exe is required to avoid killing a reused pid")
	}
	cur, err := os.Readlink("/proc/" + pidStr + "/exe")
	if err != nil {
		return "", fmt.Errorf("进程 %d 已不存在", pid)
	}
	// PID 可能已被复用：只结束可执行文件一致的进程
	if strings.TrimSuffix(cur, " (deleted)") != strings.TrimSuffix(exe, " (deleted)") {
		return "", fmt.Errorf("进程 %d 现在是 %s，不是 %s（PID 已被复用），未执行", pid, cur, exe)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return "", err
	}
	return fmt.Sprintf("已结束进程 %d（%s）", pid, cur), nil
}

// --- 隔离文件 ---

// 系统目录中的文件不允许隔离（避免误操作导致主机无法启动）；计划任务目录例外，因为常被用于持久化。
var protectedPrefixes = []string{"/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/", "/etc/", "/proc/", "/sys/", "/dev/"}
var allowedInProtected = []string{"/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/", "/etc/profile.d/"}

type quarantineMeta struct {
	Path   string      `json:"path"`
	Mode   os.FileMode `json:"mode"`
	SHA256 string      `json:"sha256"`
	Size   int64       `json:"size"`
}

func (a *Agent) quarantineDir(id string) string {
	return filepath.Join(filepath.Dir(a.cfg.StatePath), "quarantine", id)
}

func (a *Agent) quarantine(id, path string) (string, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute: %q", path)
	}
	protected := false
	for _, p := range protectedPrefixes {
		if strings.HasPrefix(path, p) {
			protected = true
		}
	}
	for _, p := range allowedInProtected {
		if strings.HasPrefix(path, p) {
			protected = false
		}
	}
	if protected || strings.HasPrefix(path, filepath.Dir(a.cfg.StatePath)) {
		return "", fmt.Errorf("系统目录中的文件不允许隔离：%s", path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("不是普通文件：%s", path)
	}
	dir := a.quarantineDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	sum, err := copyAndHash(path, filepath.Join(dir, "file"))
	if err != nil {
		return "", fmt.Errorf("复制到隔离区失败（%v）", err)
	}
	if err := os.Remove(path); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("无法从原位置删除（%v；Agent 的 systemd 沙箱只允许写入网站目录、/tmp、/etc/cron.d）", err)
	}
	meta, _ := json.Marshal(quarantineMeta{Path: path, Mode: fi.Mode().Perm(), SHA256: sum, Size: fi.Size()})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("已隔离 %s（SHA-256 %s，%d 字节）", path, sum, fi.Size()), nil
}

func (a *Agent) restoreFile(qid string) (string, error) {
	if !reActionID.MatchString(qid) {
		return "", fmt.Errorf("invalid quarantine id %q", qid)
	}
	dir := a.quarantineDir(qid)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return "", fmt.Errorf("隔离记录不存在：%s", qid)
	}
	var meta quarantineMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return "", err
	}
	if _, err := os.Lstat(meta.Path); err == nil {
		return "", fmt.Errorf("原位置已存在同名文件，未覆盖：%s", meta.Path)
	}
	if _, err := copyAndHash(filepath.Join(dir, "file"), meta.Path); err != nil {
		return "", err
	}
	if err := os.Chmod(meta.Path, meta.Mode); err != nil {
		return "", err
	}
	os.RemoveAll(dir)
	return "已恢复 " + meta.Path, nil
}

func copyAndHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		os.Remove(dst)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), out.Close()
}

// --- 隔离主机 ---

// isolationRuleset 生成隔离规则：只放行本机回环、管理中心、DNS 服务器和额外允许的地址，其余一律丢弃（含已建立的连接）。
func isolationRuleset(allow []netip.Addr) string {
	var v4, v6 []string
	for _, a := range allow {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	var in, out strings.Builder
	in.WriteString("\t\tiif \"lo\" accept\n")
	out.WriteString("\t\toif \"lo\" accept\n")
	if len(v4) > 0 {
		fmt.Fprintf(&in, "\t\tip saddr { %s } accept\n", strings.Join(v4, ", "))
		fmt.Fprintf(&out, "\t\tip daddr { %s } accept\n", strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&in, "\t\tip6 saddr { %s } accept\n", strings.Join(v6, ", "))
		fmt.Fprintf(&out, "\t\tip6 daddr { %s } accept\n", strings.Join(v6, ", "))
	}
	return "table inet safe_isolate {\n" +
		"\tchain input {\n\t\ttype filter hook input priority -10; policy drop;\n" + in.String() + "\t}\n" +
		"\tchain output {\n\t\ttype filter hook output priority -10; policy drop;\n" + out.String() + "\t}\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority -10; policy drop;\n\t}\n" +
		"}\n"
}

func (a *Agent) isolate(extra string) (string, error) {
	if !hasNft() {
		return "", errors.New("隔离主机需要 nftables（nft 命令），本机没有")
	}
	allow, err := a.managementAddrs()
	if err != nil {
		return "", err
	}
	mgmt := len(allow)
	allow = append(allow, dnsServers()...)
	for _, s := range strings.Split(extra, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ip, err := parseIP(s)
		if err != nil {
			return "", err
		}
		allow = append(allow, ip)
	}
	_ = runCmd("nft", "", "delete", "table", "inet", "safe_isolate") // 重复隔离时以新的允许列表为准
	if err := runCmd("nft", isolationRuleset(allow), "-f", "-"); err != nil {
		return "", err
	}
	return fmt.Sprintf("主机已隔离：只允许与管理中心（%d 个地址）、DNS 及 %d 个额外地址通信", mgmt, len(allow)-mgmt), nil
}

func release() (string, error) {
	if err := runCmd("nft", "", "delete", "table", "inet", "safe_isolate"); err != nil && !strings.Contains(err.Error(), "No such file") {
		return "", err
	}
	return "已解除隔离", nil
}

// managementAddrs 解析管理中心地址；隔离后必须仍能连接管理中心，才能接收解除隔离的指令。
func (a *Agent) managementAddrs() ([]netip.Addr, error) {
	u, err := url.Parse(a.cfg.ServerURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid server url %q", a.cfg.ServerURL)
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	addrs, err := net.LookupIP(u.Hostname())
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("无法解析管理中心地址 %s，拒绝隔离（隔离后将无法解除）", u.Hostname())
	}
	var out []netip.Addr
	for _, ip := range addrs {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// dnsServers 读取 DNS 服务器。使用 systemd-resolved 时 /etc/resolv.conf 只有 127.0.0.53，
// 真正的上游在 /run/systemd/resolve/resolv.conf，两者都需要放行。
func dnsServers() []netip.Addr {
	var out []netip.Addr
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
				if ip, err := netip.ParseAddr(f[1]); err == nil && !ip.IsLoopback() {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out
}
