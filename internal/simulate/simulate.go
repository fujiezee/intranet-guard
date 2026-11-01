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
)

// Scenarios 按展示顺序排列。超时时间覆盖 Agent 默认 30 秒的采集周期两轮以上。
var Scenarios = []Scenario{
	{FileTamper, "关键文件篡改", "在 /etc/cron.d 写入一个只含注释的文件，约 2 分钟后删除（模拟写计划任务持久化）",
		model.AlertFileChanged, 150 * time.Second},
	{SuspiciousProcess, "临时目录执行程序", "把系统 sleep 复制到 /tmp 并运行约 2 分钟后删除（模拟木马落地执行）",
		model.AlertSuspiciousProcess, 150 * time.Second},
	{HoneypotAccess, "访问蜜罐", "从该主机连接一个已启用的蜜罐端口（模拟失陷主机在内网探测）",
		model.AlertHoneypot, 90 * time.Second},
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
