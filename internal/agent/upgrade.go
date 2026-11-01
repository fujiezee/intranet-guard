package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"safe/internal/model"
	signing "safe/internal/release"
	"safe/internal/version"
)

// ReleaseKeys 是构建时写入的发布公钥（逗号分隔）。没有公钥的构建不接受任何升级。
var ReleaseKeys = ""

// 升级流程：下载新版本（经已有的双向 TLS 通道）→ 校验 SHA-256 和离线签名（管理中心被攻破也伪造不了）→ 新版本自检（能启动、能用本机证书通过管理中心认证、
// 版本号正确）→ 原程序改名为 .prev、新程序放到原位置 → 记录 upgrade-pending → 以 RestartExitCode 退出，
// 由 systemd / Windows 服务 / Kubernetes 重新启动为新版本 → 新版本首次上报成功后删除 .prev 和 upgrade-pending。
// 新版本启动后反复退出时，systemd 与 Kubernetes 的启动前检查（安装时写入的 upgrade-guard.sh）在第 4 次启动前
// 换回 .prev，并留下 upgrade-rolledback，旧版本启动后据此向管理中心报告升级失败。
const RestartExitCode = 75

var (
	validAttempt   = regexp.MustCompile(`^upg-[0-9a-f]{8}$`)
	validAgentFile = regexp.MustCompile(`^safe-agent-(linux|windows)-(amd64|arm64)(\.exe)?$`)
	validSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// executable 返回当前程序路径（测试中替换，避免测试替换掉真正的测试程序）。
var executable = os.Executable

type pendingUpgrade struct {
	attempt, from, to, exe string
}

func (a *Agent) upgradeFile(name string) string {
	return filepath.Join(filepath.Dir(a.cfg.StatePath), name)
}

func (a *Agent) runUpgrade(cmd model.AgentCommand) model.CommandResult {
	p := cmd.Params
	fail := func(format string, args ...any) model.CommandResult {
		detail := fmt.Sprintf(format, args...)
		slog.Warn("agent upgrade failed", "to", p["version"], "detail", detail)
		return model.CommandResult{ID: cmd.ID, Status: "error", Detail: detail}
	}
	if !validAttempt.MatchString(cmd.ID) || !validAgentFile.MatchString(p["file"]) || !validSHA256.MatchString(p["sha256"]) || p["version"] == "" {
		return fail("无效的升级指令")
	}
	if p["version"] == Version {
		return model.CommandResult{ID: cmd.ID, Status: "done", Detail: "已是该版本"}
	}
	// 旧版本也有有效签名：不允许降级，否则可以把 Agent 退回有已知漏洞的版本
	if version.Valid(Version) && version.Valid(p["version"]) && !version.Older(Version, p["version"]) {
		return fail("拒绝降级：当前版本 %s，目标版本 %s", Version, p["version"])
	}
	// 下载前先验证，签名不对时不写入也不执行任何内容
	if err := signing.Verify(ReleaseKeys, p["version"], p["file"], p["sha256"], p["signature"]); err != nil {
		return fail("发布签名验证失败：%v", err)
	}
	if a.cfg.HTTP == nil {
		return fail("未使用证书接入管理中心，不支持在线升级")
	}
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fail("找不到当前程序：%v", err)
	}
	newPath := filepath.Join(filepath.Dir(exe), ".safe-agent-upgrade"+filepath.Ext(exe))
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fail("安装目录 %s 不可写（%v）：这台主机使用旧版安装方式，请在主机上重新执行一次安装命令，之后即可在控制台升级",
			filepath.Dir(exe), err)
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(newPath)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.ServerURL+"/download/"+p["file"], nil)
	resp, err := a.cfg.HTTP.Do(req)
	if err != nil {
		f.Close()
		return fail("下载失败：%v", err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	resp.Body.Close()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case resp.StatusCode != http.StatusOK:
		return fail("下载失败：%s", resp.Status)
	case err != nil:
		return fail("下载失败：%v", err)
	case hex.EncodeToString(h.Sum(nil)) != p["sha256"]:
		return fail("下载的文件校验失败（SHA-256 不一致）")
	}

	// 自检：新版本能启动、能用本机证书通过管理中心认证、版本号与预期一致，才替换
	tctx, tcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer tcancel()
	servers := strings.Join(a.cfg.ServerURLs, ",")
	if servers == "" {
		servers = a.cfg.ServerURL
	}
	out, err := exec.CommandContext(tctx, newPath, "-self-test", "-server", servers, "-state", a.cfg.StatePath).CombinedOutput()
	if err != nil {
		return fail("新版本自检失败（%v）：%s", err, lastChars(string(out), 300))
	}
	if !strings.Contains(string(out), "version="+p["version"]+" ") {
		return fail("新版本的版本号与预期的 %s 不一致：%s", p["version"], lastChars(string(out), 200))
	}

	prev := exe + ".prev"
	os.Remove(prev)
	if err := os.Rename(exe, prev); err != nil {
		return fail("替换程序失败：%v", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		os.Rename(prev, exe)
		return fail("替换程序失败：%v", err)
	}
	ok = true
	pending := fmt.Sprintf("0\n%s\n%s\n%s\n%s\n", cmd.ID, Version, p["version"], exe)
	if err := os.WriteFile(a.upgradeFile("upgrade-pending"), []byte(pending), 0o600); err != nil {
		slog.Warn("write upgrade-pending", "err", err) // 不影响升级，只是失去自动回退
	}
	a.restartRequested = true
	slog.Info("agent upgrade installed, restarting", "from", Version, "to", p["version"])
	return model.CommandResult{ID: cmd.ID, Status: "done", Detail: "已切换到 " + p["version"] + "，正在重启"}
}

func readUpgradeFile(path string) (pendingUpgrade, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return pendingUpgrade{}, false
	}
	l := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(l) < 5 {
		return pendingUpgrade{}, false
	}
	return pendingUpgrade{attempt: l[1], from: l[2], to: l[3], exe: l[4]}, true
}

// loadUpgradeState 在启动时调用：发现上次升级被回退时向管理中心报告失败；记住待确认的升级。
func (a *Agent) loadUpgradeState() {
	if u, ok := readUpgradeFile(a.upgradeFile("upgrade-rolledback")); ok {
		os.Remove(a.upgradeFile("upgrade-rolledback"))
		slog.Warn("previous upgrade was rolled back", "to", u.to, "running", Version)
		a.results = append(a.results, model.CommandResult{ID: u.attempt, Status: "error",
			Detail: fmt.Sprintf("新版本 %s 启动后反复退出，已自动回退到 %s", u.to, u.from)})
	}
	if u, ok := readUpgradeFile(a.upgradeFile("upgrade-pending")); ok {
		a.pendingUpgrade = &u
	}
}

// commitUpgrade 在首次上报成功后调用：新版本已正常工作，清理旧程序和待确认记录。
func (a *Agent) commitUpgrade() {
	u := a.pendingUpgrade
	if u == nil {
		return
	}
	a.pendingUpgrade = nil
	os.Remove(a.upgradeFile("upgrade-pending"))
	if u.to == Version {
		os.Remove(u.exe + ".prev")
		slog.Info("agent upgrade completed", "from", u.from, "to", Version)
	}
}

func lastChars(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}
