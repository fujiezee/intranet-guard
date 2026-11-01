package alert

import "safe/internal/model"

// Stage 是攻击链中的阶段，Order 按攻击推进的先后排序。
type Stage struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Order int    `json:"order"`
}

var (
	StageNetwork     = Stage{"network", "网络攻击", 0}
	StageDiscovery   = Stage{"discovery", "侦察探测", 1}
	StageCredential  = Stage{"credential", "凭据获取", 2}
	StageInitial     = Stage{"initial", "初始访问", 3}
	StageExecution   = Stage{"execution", "执行", 4}
	StagePersistence = Stage{"persistence", "持久化", 5}
	StageEvasion     = Stage{"evasion", "防御规避", 6}
	StageLateral     = Stage{"lateral", "横向移动", 7}
	Stages           = []Stage{StageNetwork, StageDiscovery, StageCredential, StageInitial, StageExecution, StagePersistence, StageEvasion, StageLateral}
)

// incidentStages 是会形成事件的告警类型及其所属阶段。资产变化、漏洞等"卫生"类告警不形成事件。
var incidentStages = map[model.AlertType]Stage{
	model.AlertIDS:               StageNetwork,
	model.AlertHoneypot:          StageDiscovery,
	model.AlertSSHBruteForce:     StageCredential,
	model.AlertBruteForceSuccess: StageInitial,
	model.AlertRootLogin:         StageInitial,
	model.AlertSuspiciousCommand: StageExecution,
	model.AlertSuspiciousProcess: StageExecution,
	model.AlertFileChanged:       StagePersistence,
	model.AlertWebshell:          StagePersistence,
	model.AlertAgentStopped:      StageEvasion,
	model.AlertAgentOffline:      StageEvasion,
	model.AlertLateralMovement:   StageLateral,
	model.AlertAccountChange:     StagePersistence,
	model.AlertDomainAttack:      StageCredential,
}

// attachOnly 的告警只并入已有事件，不单独开启事件：Agent 停止 / 离线多数是运维操作，
// 只有发生在一次入侵过程中才值得关注。
var attachOnly = map[model.AlertType]bool{model.AlertAgentStopped: true, model.AlertAgentOffline: true, model.AlertRootLogin: true}

// IncidentStage 返回告警所属阶段；ok 为 false 表示该类告警不参与事件；canOpen 表示能否开启新事件。
func IncidentStage(t model.AlertType) (st Stage, ok, canOpen bool) {
	st, ok = incidentStages[t]
	return st, ok, ok && !attachOnly[t]
}

// StageByKey 按 key 查找阶段。
func StageByKey(key string) (Stage, bool) {
	for _, s := range Stages {
		if s.Key == key {
			return s, true
		}
	}
	return Stage{}, false
}

// RiskyPortSeverity 返回端口的风险级别（不是高危端口时 ok 为 false）。
func RiskyPortSeverity(port int) (model.Severity, bool) {
	s, ok := riskyPorts[port]
	return s, ok
}

// RuleName 返回告警类型的规则名称。
func RuleName(t model.AlertType) string {
	for _, r := range Catalog {
		if r.ID == t {
			return r.Name
		}
	}
	return string(t)
}
