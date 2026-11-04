// Package model 定义管理中心、探针、Agent 之间共享的数据结构。
package model

import "time"

type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type Asset struct {
	IP            string   `json:"ip"`
	Hostname      string   `json:"hostname,omitempty"`       // 扫描得到：反向 DNS，其次 NetBIOS
	Name          string   `json:"name,omitempty"`           // 管理员手动填写
	AgentHostname string   `json:"agent_hostname,omitempty"` // 该地址上 Agent 上报的主机名，只在资产列表 / 详情中填写
	Ports         []Port   `json:"ports"`
	ProbeID       string   `json:"probe_id"`
	Honeypot      bool     `json:"honeypot,omitempty"`   // 该地址运行着蜜罐，端口是伪装的
	Importance    string   `json:"importance,omitempty"` // normal / important / core
	Owner         string   `json:"owner,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Groups        []string `json:"groups,omitempty"` // 所属资产组名称
	// Risk 是 0-100 的风险分，RiskReasons 说明扣分项；只在资产列表 / 详情中计算
	Risk        int       `json:"risk"`
	RiskReasons []string  `json:"risk_reasons,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type TaskStatus string

const (
	TaskPending TaskStatus = "pending"
	TaskRunning TaskStatus = "running"
	TaskDone    TaskStatus = "done"
	TaskFailed  TaskStatus = "failed"
)

// ScanTask 由管理中心创建，指定探针领取后执行。
type ScanTask struct {
	ID       string   `json:"id"`
	ProbeID  string   `json:"probe_id"`
	Targets  []string `json:"targets"` // IP、CIDR 或 a.b.c.d-e 形式的范围
	Ports    []int    `json:"ports"`
	Baseline bool     `json:"baseline"` // 基线扫描：只建立资产台账，不产生告警
	Kind     TaskKind `json:"kind"`
	// WeakPassword 为 true 时漏洞检测会尝试少量常见弱口令（会产生真实的登录失败记录）。
	WeakPassword bool       `json:"weak_password"`
	Status       TaskStatus `json:"status"`
	Error        string     `json:"error,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ScanReport 是探针执行完任务后上报的结果。
type ScanReport struct {
	TaskID     string        `json:"task_id"`
	ProbeID    string        `json:"probe_id"`
	Assets     []Asset       `json:"assets"`
	Checks     []CheckResult `json:"checks,omitempty"`
	Error      string        `json:"error,omitempty"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
}

type Role string

const (
	RoleAdmin  Role = "admin"  // 全部权限：下发任务、处理告警、管理用户
	RoleViewer Role = "viewer" // 只读
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertType string

const (
	AlertNewAsset  AlertType = "new_asset"  // 首次发现的主机
	AlertNewPort   AlertType = "new_port"   // 已知主机上新开放的端口
	AlertRiskyPort AlertType = "risky_port" // 新开放的高危服务端口
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type AlertStatus string

const (
	AlertOpen  AlertStatus = "open"
	AlertAcked AlertStatus = "acked"
)

type Alert struct {
	ID       int64       `json:"id"`
	Type     AlertType   `json:"type"`
	Severity Severity    `json:"severity"`
	IP       string      `json:"ip"`
	Port     int         `json:"port,omitempty"`
	Message  string      `json:"message"`
	Status   AlertStatus `json:"status"`
	AckedBy  string      `json:"acked_by,omitempty"`
	// Resolution 为处理结果：空、false_positive（误报）或 simulation（自检产生）
	Resolution     string    `json:"resolution,omitempty"`
	IncidentID     int64     `json:"incident_id,omitempty"`
	ResolutionNote string    `json:"resolution_note,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type HostEventType string

const (
	EventLoginSuccess      HostEventType = "login_success"
	EventLoginFailed       HostEventType = "login_failed"
	EventSudo              HostEventType = "sudo"
	EventFileChanged       HostEventType = "file_changed"
	EventSuspiciousProcess HostEventType = "suspicious_process"
	EventCommand           HostEventType = "command"            // 交互式会话中执行的命令（审计，不告警）
	EventSuspiciousCommand HostEventType = "suspicious_command" // 命中命令检测规则
	EventWebshell          HostEventType = "webshell"           // 网站目录脚本文件新增 / 修改
	EventAccountChange     HostEventType = "account_change"     // 新建账户、加入特权组（Windows）
	EventDomainAttack      HostEventType = "domain_attack"      // 域控上的攻击迹象：Kerberoasting、DCSync 等
)

// HostEvent 是主机 Agent 采集到的一条审计事件。
type HostEvent struct {
	ID      int64         `json:"id,omitempty"`
	AgentID string        `json:"agent_id,omitempty"` // 由管理中心填写
	Type    HostEventType `json:"type"`
	Time    time.Time     `json:"time"`
	User    string        `json:"user,omitempty"`
	SrcIP   string        `json:"src_ip,omitempty"`
	Path    string        `json:"path,omitempty"`
	Detail  string        `json:"detail,omitempty"`
	// Severity 是 Agent 侧规则给出的级别（high / medium），只用于生成告警，不持久化。
	Severity string `json:"severity,omitempty"`
}

type AgentStatus string

const (
	AgentOnline  AgentStatus = "online"
	AgentOffline AgentStatus = "offline"
	AgentStopped AgentStatus = "stopped" // 收到停止信号后主动告知（关机、systemctl stop 等）
)

type AgentInfo struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Version  string   `json:"version"`
	IPs      []string `json:"ips"`
	// Capabilities 是本机实际生效的采集能力（如 exec_monitor），便于在控制台发现降级运行
	Capabilities []string    `json:"capabilities,omitempty"`
	Stopping     bool        `json:"stopping,omitempty"` // 本次上报是停止前的最后一次
	Status       AgentStatus `json:"status,omitempty"`
	LastSeen     time.Time   `json:"last_seen,omitempty"`
}

// AgentReport 是 Agent 定期上报的心跳 + 事件批次。
type AgentReport struct {
	Agent   AgentInfo       `json:"agent"`
	Events  []HostEvent     `json:"events"`
	Results []CommandResult `json:"results,omitempty"`
}

// AgentReportResponse 是上报的回复，带回待执行的指令。
type AgentReportResponse struct {
	Commands []AgentCommand `json:"commands"`
}

const (
	AlertSSHBruteForce     AlertType = "ssh_bruteforce"
	AlertBruteForceSuccess AlertType = "bruteforce_success" // 爆破来源随后登录成功
	AlertRootLogin         AlertType = "root_login"
	AlertFileChanged       AlertType = "file_changed"
	AlertSuspiciousProcess AlertType = "suspicious_process"
	AlertAgentOffline      AlertType = "agent_offline"
	AlertAgentStopped      AlertType = "agent_stopped"
	AlertSuspiciousCommand AlertType = "suspicious_command"
	AlertWebshell          AlertType = "webshell"
	AlertLateralMovement   AlertType = "lateral_movement"
	AlertAccountChange     AlertType = "account_change"
	AlertDomainAttack      AlertType = "domain_attack"
	AlertUpgradeRejected   AlertType = "upgrade_rejected" // Agent 拒绝了未通过发布签名验证的升级包
	AlertProbeOffline      AlertType = "probe_offline"    // 探针长时间没有与管理中心通信
	AlertIDSSilent         AlertType = "ids_silent"       // 探针在线，但长时间没有上报 IDS 事件
)

// IDSEvent 是探针从 Suricata 告警中归一化出的流量检测事件。
type IDSEvent struct {
	ID          int64     `json:"id,omitempty"`
	ProbeID     string    `json:"probe_id,omitempty"` // 由管理中心填写
	Time        time.Time `json:"time"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     int       `json:"src_port,omitempty"`
	DestIP      string    `json:"dest_ip"`
	DestPort    int       `json:"dest_port,omitempty"`
	Proto       string    `json:"proto"`
	AppProto    string    `json:"app_proto,omitempty"`
	SignatureID int64     `json:"signature_id"`
	Signature   string    `json:"signature"`
	Category    string    `json:"category,omitempty"`
	Severity    int       `json:"severity"` // Suricata 优先级：1 最高
	Action      string    `json:"action,omitempty"`
	Suppressed  bool      `json:"suppressed,omitempty"`
}

type IDSReport struct {
	ProbeID string     `json:"probe_id"`
	Events  []IDSEvent `json:"events"`
}

// IDSSuppression 抑制指定规则的告警；SrcIP 为空表示对所有来源生效。
type IDSSuppression struct {
	ID          int64     `json:"id"`
	SignatureID int64     `json:"signature_id"`
	SrcIP       string    `json:"src_ip,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

const AlertIDS AlertType = "ids"

type NodeKind string

const (
	NodeProbe NodeKind = "probe"
	NodeAgent NodeKind = "agent"
)

type NodeStatus string

const (
	NodeActive  NodeStatus = "active"
	NodeRevoked NodeStatus = "revoked"
)

// Node 是通过证书注册的探针或 Agent。
type Node struct {
	Kind       NodeKind   `json:"kind"`
	ID         string     `json:"id"`
	Serial     string     `json:"serial"`
	Status     NodeStatus `json:"status"`
	CertExpiry time.Time  `json:"cert_expiry"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	TokenID    int64      `json:"token_id"`
}

// EnrollToken 允许节点注册；明文令牌只在创建时返回一次。
type EnrollToken struct {
	ID        int64     `json:"id"`
	Kind      NodeKind  `json:"kind"`
	MaxUses   int       `json:"max_uses"`
	Uses      int       `json:"uses"`
	ExpiresAt time.Time `json:"expires_at"`
	Note      string    `json:"note,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type TaskKind string

const (
	TaskDiscovery TaskKind = "discovery" // 资产发现：端口扫描
	TaskVuln      TaskKind = "vuln"      // 漏洞检测：端口扫描 + 未授权访问 / 弱口令检查
)

// CheckResult 是对某个端口执行一项检查的结果。Vulnerable=false 表示检查已执行且未发现问题，
// 管理中心据此把之前发现的同一漏洞标记为已修复。
type CheckResult struct {
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	CheckID    string   `json:"check_id"`
	Vulnerable bool     `json:"vulnerable"`
	Title      string   `json:"title,omitempty"`
	Severity   Severity `json:"severity,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

type VulnStatus string

const (
	VulnOpen    VulnStatus = "open"
	VulnFixed   VulnStatus = "fixed"
	VulnIgnored VulnStatus = "ignored" // 人工确认为可接受的风险，复查仍存在也不再告警
)

type Vuln struct {
	ID        int64      `json:"id"`
	IP        string     `json:"ip"`
	Port      int        `json:"port"`
	CheckID   string     `json:"check_id"`
	Title     string     `json:"title"`
	Severity  Severity   `json:"severity"`
	Detail    string     `json:"detail"`
	Status    VulnStatus `json:"status"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	FixedAt   *time.Time `json:"fixed_at,omitempty"`
}

const AlertVuln AlertType = "vuln"

type ChannelType string

const (
	ChannelWeCom    ChannelType = "wecom"    // 企业微信群机器人
	ChannelDingTalk ChannelType = "dingtalk" // 钉钉群机器人
	ChannelFeishu   ChannelType = "feishu"   // 飞书群机器人
	ChannelWebhook  ChannelType = "webhook"  // 通用 Webhook，POST JSON
)

// NotifyChannel 是告警推送渠道。URL 和 Secret 只在创建时提交，列表接口返回脱敏后的 URL。
type NotifyChannel struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	Type        ChannelType `json:"type"`
	URL         string      `json:"url"`
	Secret      string      `json:"secret,omitempty"` // 钉钉 / 飞书加签密钥
	MinSeverity Severity    `json:"min_severity"`
	Enabled     bool        `json:"enabled"`
	LastError   string      `json:"last_error,omitempty"`
	LastSentAt  *time.Time  `json:"last_sent_at,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
}

// AuditEntry 记录一次管理操作。
type AuditEntry struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	ClientIP string    `json:"client_ip"`
	Success  bool      `json:"success"`
}

// HoneypotService 是探针上的一个伪装服务。
type HoneypotService struct {
	Type string `json:"type"` // ssh / ftp / telnet / mysql / redis / http / tcp
	Port int    `json:"port"`
}

// HoneypotConfig 是管理中心下发给探针的蜜罐配置。
type HoneypotConfig struct {
	Enabled       bool              `json:"enabled"`
	Services      []HoneypotService `json:"services"`
	IgnoreSources []string          `json:"ignore_sources"` // 不告警的来源（CIDR），如内部漏洞扫描器
}

// HoneypotEvent 是一次对蜜罐的访问。正常业务不会访问蜜罐，因此每一条都值得关注。
type HoneypotEvent struct {
	ID           int64     `json:"id,omitempty"`
	ProbeID      string    `json:"probe_id,omitempty"` // 由管理中心填写
	Time         time.Time `json:"time"`
	Service      string    `json:"service"`
	Port         int       `json:"port"`
	SrcIP        string    `json:"src_ip"`
	SrcPort      int       `json:"src_port"`
	Username     string    `json:"username,omitempty"`
	Password     string    `json:"password,omitempty"` // 只保留首字符和长度
	Detail       string    `json:"detail,omitempty"`
	SimulationID string    `json:"simulation_id,omitempty"` // 攻击模拟自检产生的访问
}

const AlertHoneypot AlertType = "honeypot"

// AgentCommand 是管理中心随上报回复下发给 Agent 的指令：攻击模拟自检或处置动作。
type AgentCommand struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`               // simulate / action
	Scenario string            `json:"scenario,omitempty"` // simulate
	Action   string            `json:"action,omitempty"`   // action：处置动作类型
	Params   map[string]string `json:"params,omitempty"`
	// ExpiresAt 之后 Agent 拒绝执行，防止网络中断后迟到的处置被执行
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// CommandResult 是 Agent 执行指令后的结果，在下一次上报时带回。
type CommandResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // done / not_applicable / error
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"` // 需要管理中心专门处理的失败原因
}

// ResultSignatureRejected：升级包没有通过发布签名验证。
const ResultSignatureRejected = "signature_rejected"

type SimulationStatus string

const (
	SimPending       SimulationStatus = "pending"
	SimRunning       SimulationStatus = "running"
	SimPassed        SimulationStatus = "passed"
	SimFailed        SimulationStatus = "failed" // 超时未检测到
	SimNotApplicable SimulationStatus = "not_applicable"
	SimError         SimulationStatus = "error"
)

type Simulation struct {
	ID         string           `json:"id"`
	AgentID    string           `json:"agent_id"`
	Scenario   string           `json:"scenario"`
	Status     SimulationStatus `json:"status"`
	Detail     string           `json:"detail,omitempty"`
	AlertID    int64            `json:"alert_id,omitempty"`
	LatencyMs  int64            `json:"latency_ms,omitempty"` // 从 Agent 领取到告警产生
	CreatedBy  string           `json:"created_by"`
	CreatedAt  time.Time        `json:"created_at"`
	StartedAt  *time.Time       `json:"started_at,omitempty"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

// 告警处理结果
const (
	ResolutionFalsePositive = "false_positive"
	ResolutionSimulation    = "simulation" // 攻击模拟自检产生，不推送
)

// 处置动作类型。每个动作都有对应的撤销动作。
const (
	ActBlockIP     = "block_ip"
	ActUnblockIP   = "unblock_ip"
	ActKillProcess = "kill_process"
	ActQuarantine  = "quarantine_file"
	ActRestoreFile = "restore_file"
	ActIsolate     = "isolate_host"
	ActRelease     = "release_host"
)

type ActionStatus string

const (
	ActAwaitingApproval ActionStatus = "awaiting_approval" // 需要另一位管理员批准
	ActPending          ActionStatus = "pending"           // 等待 Agent 领取
	ActSent             ActionStatus = "sent"
	ActDone             ActionStatus = "done"
	ActFailed           ActionStatus = "failed"
	ActExpired          ActionStatus = "expired"     // 超时未领取 / 未批准
	ActRolledBack       ActionStatus = "rolled_back" // 已被撤销动作抵消
)

// ResponseAction 是一次处置。
type ResponseAction struct {
	ID         string            `json:"id"`
	AgentID    string            `json:"agent_id"`
	Type       string            `json:"type"`
	Params     map[string]string `json:"params"`
	Reason     string            `json:"reason"`
	Status     ActionStatus      `json:"status"`
	Result     string            `json:"result,omitempty"`
	CreatedBy  string            `json:"created_by"`
	ApprovedBy string            `json:"approved_by,omitempty"`
	RollbackOf string            `json:"rollback_of,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentResolved      IncidentStatus = "resolved"
	IncidentFalsePositive IncidentStatus = "false_positive"
)

// Incident 是同一主机一段时间内的入侵类告警的集合，代表一次（疑似）入侵。
type Incident struct {
	ID         int64          `json:"id"`
	IP         string         `json:"ip"`
	Title      string         `json:"title"`
	Severity   Severity       `json:"severity"`
	Status     IncidentStatus `json:"status"`
	Assignee   string         `json:"assignee,omitempty"`
	Stages     []string       `json:"stages"` // 涉及的攻击阶段 key，按攻击链顺序
	AlertCount int            `json:"alert_count"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type IncidentNote struct {
	ID        int64     `json:"id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// 资产重要性：用于风险评分加权和处置时的提示。
const (
	ImportanceNormal    = "normal"
	ImportanceImportant = "important"
	ImportanceCore      = "core"
)

const (
	AlertThreatIntel AlertType = "threat_intel" // 与威胁情报中的地址 / 域名通信
	AlertDNSAnomaly  AlertType = "dns_anomaly"  // DGA、DNS 隧道
	AlertBeacon      AlertType = "c2_beacon"    // 周期性外联（C2 心跳）
	AlertExfil       AlertType = "exfiltration" // 非工作时间大流量外传
)

// IntelIndicator 是一条威胁情报（管理中心存储的形式）。
type IntelIndicator struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"` // ip / cidr / domain
	Value     string    `json:"value"`
	Source    string    `json:"source"` // manual 或 feed:<id>
	Severity  Severity  `json:"severity"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// IntelFeed 是一个情报订阅源：纯文本，每行一个 IP / 网段 / 域名（兼容 hosts 文件格式）。
type IntelFeed struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Severity  Severity   `json:"severity"`
	Enabled   bool       `json:"enabled"`
	Count     int        `json:"count"`
	LastFetch *time.Time `json:"last_fetch,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

// 资产组类型
const (
	GroupCluster = "cluster" // 集群：成员之间互相登录属于正常
	GroupAdmin   = "admin"   // 运维跳板 / 自动化：成员登录任何主机都属于正常
)

// AssetGroup 按网段 / 地址把资产归组，用于展示和降低横向移动误报。
type AssetGroup struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Members   []string  `json:"members"` // IP 或 CIDR
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIToken 是外部工具（MCP 等）使用的只读令牌，只保存哈希。
type APIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}
