package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Windows 上用 Windows 防火墙封禁 IP：每个地址一对入站 / 出站阻止规则，名称 "safe-block <IP>"。
// 防火墙规则没有到期时间，到期时间记录在状态目录的 firewall-blocks.json 中，由 Agent 每个周期解除（重启后仍然有效）。

func winBlockRule(ip netip.Addr) string { return "safe-block " + ip.String() }

// parseBlockArgs 校验封禁参数（各平台共用）。
func parseBlockArgs(ipStr, durStr string) (netip.Addr, int, error) {
	ip, err := parseIP(ipStr)
	if err != nil {
		return ip, 0, err
	}
	secs, err := strconv.Atoi(durStr)
	if err != nil || secs < 60 {
		return ip, 0, fmt.Errorf("invalid duration %q", durStr)
	}
	return ip, secs, nil
}

func (a *Agent) winBlocksPath() string {
	return filepath.Join(filepath.Dir(a.cfg.StatePath), "firewall-blocks.json")
}

func (a *Agent) loadWinBlocks() map[string]int64 {
	m := map[string]int64{}
	if b, err := os.ReadFile(a.winBlocksPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (a *Agent) saveWinBlocks(m map[string]int64) error {
	b, _ := json.Marshal(m)
	return os.WriteFile(a.winBlocksPath(), b, 0o600)
}

func (a *Agent) winBlockIP(ipStr, durStr string) (string, error) {
	ip, secs, err := parseBlockArgs(ipStr, durStr)
	if err != nil {
		return "", err
	}
	name := winBlockRule(ip)
	_ = runCmd("netsh", "", "advfirewall", "firewall", "delete", "rule", "name="+name) // 重复封禁时以新的时长为准
	for _, dir := range []string{"in", "out"} {
		if err := runCmd("netsh", "", "advfirewall", "firewall", "add", "rule", "name="+name, "dir="+dir,
			"action=block", "remoteip="+ip.String(), "enable=yes"); err != nil {
			_ = runCmd("netsh", "", "advfirewall", "firewall", "delete", "rule", "name="+name)
			return "", err
		}
	}
	blocks := a.loadWinBlocks()
	blocks[ip.String()] = time.Now().Add(time.Duration(secs) * time.Second).Unix()
	if err := a.saveWinBlocks(blocks); err != nil {
		return "", err
	}
	return fmt.Sprintf("Windows 防火墙已封禁 %s（%d 秒后由 Agent 解除；需要 Windows 防火墙处于启用状态）", ip, secs), nil
}

func (a *Agent) winUnblockIP(ipStr string) (string, error) {
	ip, err := parseIP(ipStr)
	if err != nil {
		return "", err
	}
	if err := runCmd("netsh", "", "advfirewall", "firewall", "delete", "rule", "name="+winBlockRule(ip)); err != nil {
		slog.Warn("delete firewall rule", "ip", ip, "err", err) // 规则可能已被手动删除，以状态为准
	}
	blocks := a.loadWinBlocks()
	delete(blocks, ip.String())
	if err := a.saveWinBlocks(blocks); err != nil {
		return "", err
	}
	return "已解除对 " + ip.String() + " 的封禁", nil
}

// sweepWinBlocks 解除已到期的封禁。
func (a *Agent) sweepWinBlocks() {
	blocks := a.loadWinBlocks()
	now := time.Now().Unix()
	for ip, until := range blocks {
		if until <= now {
			if _, err := a.winUnblockIP(ip); err != nil {
				slog.Warn("unblock expired ip", "ip", ip, "err", err)
				continue
			}
			slog.Info("block expired", "ip", ip)
		}
	}
}
