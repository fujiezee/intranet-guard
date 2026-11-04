package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"safe/internal/model"
	"safe/internal/netintel"
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
			Message: fmt.Sprintf("%s (%s) 遭受暴力破解：来源 %s 在 %d 分钟内登录失败 %d 次",
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

// ProbeOffline：探针失联。DedupKey 用于恢复后自动确认这条告警。
func ProbeOffline(probeIP, probeID string, lastSeen time.Time) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertProbeOffline, Severity: model.SeverityHigh, IP: probeIP,
			Message: fmt.Sprintf("探针 %s 离线，最后通信 %s；网段扫描、蜜罐与流量检测已中断",
				probeID, lastSeen.Local().Format("2006-01-02 15:04:05")),
		},
		DedupKey: ProbeOfflineKey(probeID),
	}
}

// IDSSilent：探针在线但 eve.json 不再增长，多为 Suricata 停止或 eve 输出路径变了。
// 不按 IDS 告警判断：告警只在规则命中时产生，网络安静时没有告警是正常的。
func IDSSilent(probeIP, probeID string, lastEve time.Time) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertIDSSilent, Severity: model.SeverityMedium, IP: probeIP,
			Message: fmt.Sprintf("探针 %s 在线，但 Suricata 的 eve.json 自 %s 起没有新内容；检查 Suricata 是否在运行、-eve 路径是否正确",
				probeID, lastEve.Local().Format("2006-01-02 15:04:05")),
		},
		DedupKey: IDSSilentKey(probeID),
	}
}

func ProbeOfflineKey(probeID string) string { return "probe-offline:" + probeID }
func IDSSilentKey(probeID string) string    { return "ids-silent:" + probeID }

// UpgradeRejected：Agent 拒绝了升级包。问题在管理中心一侧，同一版本只告警一次，多台 Agent 拒绝不会形成告警风暴。
func UpgradeRejected(hostIP, agentID, target string) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{
			Type: model.AlertUpgradeRejected, Severity: model.SeverityHigh, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 拒绝了版本 %s 的升级包：发布签名验证失败。升级包可能被替换，或管理中心已被攻破；也可能部署了未签名的安装包。自动升级已暂停",
				hostIP, agentID, target),
		},
		DedupKey: "upgrade-rejected:" + target,
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

// AccountChange：新建账户或加入特权组，常见于攻击者建立持久化后门账户。
func AccountChange(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertAccountChange, Severity: severityOf(ev.Severity), IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 账户变更：%s", hostIP, agentID, ev.Detail)},
		DedupKey: "acct:" + agentID + ":" + shortHash(ev.Detail),
	}
}

// DomainAttack：域控上的攻击迹象（Kerberoasting、AS-REP Roasting、DCSync、凭据传递）。
func DomainAttack(hostIP, agentID string, ev model.HostEvent) DedupAlert {
	msg := fmt.Sprintf("%s (%s) 域攻击迹象：%s", hostIP, agentID, ev.Detail)
	if ev.SrcIP != "" {
		msg += "；来源 " + ev.SrcIP
	}
	return DedupAlert{
		Alert:    model.Alert{Type: model.AlertDomainAttack, Severity: severityOf(ev.Severity), IP: hostIP, Message: msg},
		DedupKey: "domain:" + agentID + ":" + shortHash(ev.Detail),
	}
}

var netFindingTypes = map[string]model.AlertType{"intel": model.AlertThreatIntel, "dga": model.AlertDNSAnomaly,
	"dns_tunnel": model.AlertDNSAnomaly, "beacon": model.AlertBeacon, "exfil": model.AlertExfil}

// NetFinding 把探针的网络分析结果转为告警，关联到内网中的相关主机。
func NetFinding(probeID string, f netintel.Finding) DedupAlert {
	typ, ok := netFindingTypes[f.Kind]
	if !ok {
		typ = model.AlertThreatIntel
	}
	return DedupAlert{
		Alert:    model.Alert{Type: typ, Severity: severityOf(f.Severity), IP: f.SrcIP, Message: f.Detail + "（探针 " + probeID + "）"},
		DedupKey: "net:" + f.Kind + ":" + f.SrcIP + ":" + f.Peer,
	}
}

// IntelLogin：登录来源在威胁情报中。
func IntelLogin(hostIP, agentID string, ev model.HostEvent, ind netintel.Indicator) DedupAlert {
	what := "登录成功"
	sev := model.SeverityHigh
	if ev.Type == model.EventLoginFailed {
		what, sev = "尝试登录", model.SeverityMedium
	}
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertThreatIntel, Severity: sev, IP: hostIP,
			Message: fmt.Sprintf("%s (%s) 威胁情报地址 %s %s（用户 %s，情报来源：%s）", hostIP, agentID, ev.SrcIP, what, ev.User, ind.Source)},
		DedupKey: "intel-login:" + agentID + ":" + ev.SrcIP + ":" + string(ev.Type),
	}
}

// IntelIDS：IDS 告警中的对端地址在威胁情报中。
func IntelIDS(hostIP, peer string, ev model.IDSEvent, ind netintel.Indicator) DedupAlert {
	return DedupAlert{
		Alert: model.Alert{Type: model.AlertThreatIntel, Severity: model.SeverityHigh, IP: hostIP,
			Message: fmt.Sprintf("%s 与威胁情报地址 %s 的通信触发 IDS 规则「%s」（情报来源：%s）", hostIP, peer, ev.Signature, ind.Source)},
		DedupKey: "intel-ids:" + hostIP + ":" + peer,
	}
}
