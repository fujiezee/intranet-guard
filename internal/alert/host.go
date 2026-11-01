package alert

import (
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
