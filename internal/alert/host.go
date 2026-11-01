package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"safe/internal/model"
)

const (
	// BruteForceThreshold 次失败登录出现在 BruteForceWindow 内即判定为爆破。
	BruteForceThreshold = 10
	BruteForceWindow    = 5 * time.Minute
	// BruteForceLookback 内有过爆破的来源随后登录成功，判定为爆破成功。
	BruteForceLookback = time.Hour
	// DedupWindow 内相同 dedup key 的告警不重复产生。
	DedupWindow = 30 * time.Minute
)

// criticalFiles 被修改通常意味着账号、权限或持久化被篡改。
var criticalFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload", "authorized_keys",
	"/etc/crontab", "/etc/cron.d/", "/var/spool/cron", "/etc/pam.d/", "/etc/ssh/sshd_config",
}

// DedupAlert 带去重键，DedupWindow 内相同 key 的告警只产生一次。
type DedupAlert struct {
	model.Alert
	DedupKey string
}

func SSHBruteForce(hostIP, agentID, srcIP string, failures int) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertSSHBruteForce, Severity: model.SeverityHigh, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 遭受 SSH 爆破：来源 %s 在 %d 分钟内失败登录 %d 次",
				hostIP, agentID, srcIP, int(BruteForceWindow.Minutes()), failures),
		},
		DedupKey: "bruteforce:" + agentID + ":" + srcIP,
	}
}

func BruteForceSuccess(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertBruteForceSuccess, Severity: model.SeverityHigh, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 疑似被爆破成功：爆破来源 %s 以用户 %s 登录成功", hostIP, agentID, ev.SrcIP, ev.User),
		},
		DedupKey: "bfsuccess:" + agentID + ":" + ev.SrcIP + ":" + ev.User,
	}
}

func RootLogin(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertRootLogin, Severity: model.SeverityMedium, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) root 远程登录，来源 %s（%s）", hostIP, agentID, ev.SrcIP, ev.Detail),
		},
		DedupKey: "rootlogin:" + agentID + ":" + ev.SrcIP,
	}
}

func FileChanged(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	sev := model.SeverityMedium
	for _, c := range criticalFiles {
		if strings.Contains(ev.Path, c) {
			sev = model.SeverityHigh
			break
		}
	}
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertFileChanged, Severity: sev, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 关键文件变更：%s %s", hostIP, agentID, ev.Path, ev.Detail),
		},
	}
}

func SuspiciousProcess(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	// 软件升级后未重启的服务也会表现为可执行文件已删除，级别低于临时目录运行。
	sev := model.SeverityHigh
	if strings.Contains(ev.Detail, "executable deleted") {
		sev = model.SeverityMedium
	}
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertSuspiciousProcess, Severity: sev, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 可疑进程：%s（%s）", hostIP, agentID, ev.Path, ev.Detail),
		},
	}
}

func AgentOffline(hostIP, agentID string, lastSeen time.Time) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertAgentOffline, Severity: model.SeverityMedium, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) Agent 离线，最后心跳 %s；可能是宕机、网络中断或 Agent 被停止",
				hostIP, agentID, lastSeen.Local().Format("2006-01-02 15:04:05")),
		},
	}
}

// Honeypot 为一次蜜罐访问生成告警。告警关联到访问来源：内网中访问蜜罐的主机很可能已失陷或正在被用于探测。
func Honeypot(probeID string, ev model.HoneypotEvent) DedupAlert {
	msg := fmt.Sprintf("%s 访问了蜜罐（探针 %s 的 %s 服务，端口 %d）：%s", ev.SrcIP, probeID, ev.Service, ev.Port, ev.Detail)
	if ev.Username != "" {
		msg += "，尝试用户 " + ev.Username
		if ev.Password != "" {
			msg += " 密码 " + ev.Password
		}
	}
	key := "honeypot:" + ev.SrcIP + ":" + ev.Service
	if ev.SimulationID != "" {
		key += ":" + ev.SimulationID
	}
	return DedupAlert{
		Alert:    model.Alert{Type: model.AlertHoneypot, Severity: model.SeverityHigh, IP: ev.SrcIP, Port: ev.Port, Message: msg},
		DedupKey: key,
	}
}

const (
	// LateralTargets 台及以上主机在 LateralWindow 内被同一来源登录，判定为横向移动。
	LateralTargets = 5
	LateralWindow  = 10 * time.Minute
)

func severityOf(s string) model.Severity {
	if s == "high" {
		return model.SeverityHigh
	}
	return model.SeverityMedium
}

// SuspiciousCommand 为命中命令检测规则的执行生成告警。相同主机上相同的命令 30 分钟内只告警一次。
func SuspiciousCommand(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	msg := fmt.Sprintf("%s (%s) 可疑命令，用户 %s：%s", hostIP, agentID, ev.User, ev.Detail)
	if ev.SrcIP != "" {
		msg += "；连接对端 " + ev.SrcIP
	}
	return DedupAlert{
		Alert:    model.Alert{Type: model.AlertSuspiciousCommand, Severity: severityOf(ev.Severity), IP: hostIP, Message: msg},
		DedupKey: "cmd:" + agentID + ":" + shortHash(ev.Detail),
	}
}

// Webshell 为网站目录中新增或修改的脚本文件生成告警。
func Webshell(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertWebshell, Severity: severityOf(ev.Severity), IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 疑似 Webshell：%s %s", hostIP, agentID, ev.Path, ev.Detail)},
	}
}

// LateralMovement：同一来源短时间登录多台主机。告警关联到来源（它很可能已失陷）。
func LateralMovement(srcIP, user string, targets int) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertLateralMovement, Severity: model.SeverityHigh, IP: srcIP,
			Message: fmt.Sprintf("疑似横向移动：%s 在 %d 分钟内（以用户 %s 等）登录了 %d 台主机",
				srcIP, int(LateralWindow.Minutes()), user, targets)},
		DedupKey: "lateral:" + srcIP,
	}
}

// AgentStopped：Agent 收到停止信号。可能是关机 / 重启、运维停止，也可能是攻击者在清除监控。
func AgentStopped(hostIP, agentID string) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertAgentStopped, Severity: model.SeverityMedium, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) Agent 被停止：主机关机 / 重启、运维停止服务，或攻击者在清除监控；如非计划内操作请排查", hostIP, agentID)},
		DedupKey: "agentstop:" + agentID,
	}
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
