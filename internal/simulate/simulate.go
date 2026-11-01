// Package simulate 定义攻击模拟自检的场景。场景只包含预先定义的无害动作，
// 产生的文件、进程、网络请求都带自检编号，管理中心据此把触发的告警关联到自检并且不推送。
package simulate

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"

	"safe/internal/model"
)

type Scenario struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Expect      model.AlertType `json:"expect"`  // 预期触发的告警类型
	Timeout     time.Duration   `json:"timeout"` // 从 Agent 领取到告警出现的最长时间
}

const (
	FileTamper        = "fim"
	SuspiciousProcess = "process"
	HoneypotAccess    = "honeypot"
	ReverseShell      = "reverse_shell"
	DownloadExec      = "download_exec"
	WebshellDrop      = "webshell"
)

// Scenarios 按展示顺序排列。超时时间覆盖 Agent 默认 30 秒的采集周期两轮以上。
var Scenarios = []Scenario{
	{FileTamper, "关键文件篡改", "在 /etc/cron.d 写入一个只含注释的文件，约 2 分钟后删除（模拟写计划任务持久化）",
		model.AlertFileChanged, 150 * time.Second},
	{SuspiciousProcess, "临时目录执行程序", "把系统 sleep 复制到 /tmp 并运行约 2 分钟后删除（模拟木马落地执行）",
		model.AlertSuspiciousProcess, 150 * time.Second},
	{HoneypotAccess, "访问蜜罐", "从该主机连接一个已启用的蜜罐端口（模拟失陷主机在内网探测）",
		model.AlertHoneypot, 90 * time.Second},
	{ReverseShell, "反弹 shell", "启动一个 shell，其输入输出连接到 Agent 在本机建立的 TCP 连接（不连接外部、不执行任何命令），2 分钟后结束",
		model.AlertSuspiciousCommand, 150 * time.Second},
	{DownloadExec, "下载并执行", "执行一条包含 \"curl … | sh\" 字样的命令，实际为空操作（不下载、不执行），2 分钟后结束",
		model.AlertSuspiciousCommand, 150 * time.Second},
	{WebshellDrop, "Webshell 落地", "在网站目录写入一个只含注释的 PHP 文件（无任何代码），2 分钟后删除",
		model.AlertWebshell, 150 * time.Second},
}

func Get(id string) (Scenario, bool) {
	for _, s := range Scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// IDPattern 匹配告警内容中的自检编号。
var IDPattern = regexp.MustCompile(`sim-[0-9a-f]{8}`)

func NewID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "sim-" + hex.EncodeToString(b)
}
