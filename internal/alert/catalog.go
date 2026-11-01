package alert

import "safe/internal/model"

// Rule 描述一条检测规则：对应的告警类型、ATT&CK 技术、说明、处置建议，以及能验证它的自检场景。
type Rule struct {
	ID          model.AlertType `json:"id"`
	Name        string          `json:"name"`
	Tactic      string          `json:"tactic"`               // ATT&CK 战术（中文）
	Techniques  []string        `json:"techniques"`           // ATT&CK 技术编号
	Severity    string          `json:"severity"`             // 默认级别（部分规则按情况分级）
	Source      string          `json:"source"`               // 数据来源
	Description string          `json:"description"`          // 触发条件
	Response    string          `json:"response"`             // 处置建议
	Simulation  string          `json:"simulation,omitempty"` // 能验证该规则的自检场景
}

// Catalog 是全部检测规则。新增告警类型时必须在这里登记，并尽量提供自检场景。
var Catalog = []Rule{
	{model.AlertHoneypot, "访问蜜罐", "发现 / 横向移动", []string{"T1046", "T1021"}, "高", "蜜罐（探针）",
		"任何主机连接蜜罐端口、尝试登录或执行命令。正常业务不会访问蜜罐。",
		"立即排查来源主机：近期登录、进程、外联；确认失陷后隔离。若来源是授权的扫描器，在蜜罐忽略列表中加入它。", "honeypot"},
	{model.AlertSSHBruteForce, "暴力破解", "凭据获取", []string{"T1110.001"}, "高", "主机 Agent（auth 日志）",
		"同一来源 5 分钟内 SSH 登录失败 ≥ 10 次。",
		"封禁来源 IP；检查目标主机是否有弱口令账号；考虑禁用密码登录。", ""},
	{model.AlertBruteForceSuccess, "爆破后登录成功", "凭据获取 / 初始访问", []string{"T1110", "T1078"}, "高", "主机 Agent（auth 日志）",
		"1 小时内有过爆破的来源随后登录成功。",
		"按已失陷处理：隔离主机、修改该账号密码、排查登录后的操作和持久化。", ""},
	{model.AlertRootLogin, "root 远程登录", "初始访问 / 权限维持", []string{"T1078.003"}, "中", "主机 Agent（auth 日志）",
		"root 账号通过 SSH 登录成功。",
		"确认是否为授权运维；建议禁止 root 直接登录，改用普通账号 + sudo。", ""},
	{model.AlertFileChanged, "关键文件篡改", "持久化", []string{"T1053.003", "T1098.004", "T1574.006", "T1136"}, "高 / 中", "主机 Agent（文件完整性）",
		"账号、权限、SSH 公钥、计划任务、动态库预加载、PAM、systemd 等关键文件被新增、修改、删除或改权限。",
		"核对变更内容和变更人；非授权变更按失陷处理，检查新增的账号、公钥、计划任务。", "fim"},
	{model.AlertSuspiciousProcess, "可疑进程", "执行 / 防御规避", []string{"T1059", "T1036", "T1070.004"}, "高 / 中", "主机 Agent（进程）",
		"从 /tmp、/var/tmp、/dev/shm 运行的程序，或可执行文件已被删除仍在运行（软件升级未重启也会出现，级别为中）。",
		"查看进程命令行、父进程、网络连接；确认恶意后结束进程并保留样本。", "process"},
	{model.AlertSuspiciousCommand, "可疑命令", "执行 / 命令控制 / 防御规避",
		[]string{"T1059.004", "T1105", "T1505.003", "T1496", "T1070.003"}, "高 / 中", "主机 Agent（命令审计）",
		"反弹 shell（shell 输入输出连到 TCP 连接，或命令特征）、下载并执行、Web 服务派生 shell 或侦察命令、挖矿、清除历史与日志。",
		"立即查看命令的用户、父进程和网络连接；反弹 shell / 下载执行按失陷处理，封禁对端地址并隔离主机。", "reverse_shell"},
	{model.AlertWebshell, "Webshell", "持久化", []string{"T1505.003"}, "高 / 中", "主机 Agent（网站目录）",
		"网站目录中新增或修改脚本文件（.php / .jsp / .asp 等）；含 eval、编码混淆、命令执行等特征为高。",
		"确认是否为正常发布；可疑文件先备份再删除，排查上传入口和 Web 访问日志。", "webshell"},
	{model.AlertLateralMovement, "横向移动", "横向移动", []string{"T1021.004", "T1078"}, "高", "主机 Agent（auth 日志）",
		"同一内网来源 10 分钟内成功登录 5 台以上主机。",
		"确认来源是否为跳板机或自动化运维；否则按失陷处理来源主机。跳板机产生的告警可标记误报。", ""},
	{model.AlertAccountChange, "账户变更", "持久化 / 权限提升", []string{"T1136.001", "T1136.002", "T1098"}, "高 / 中",
		"Windows Agent（安全日志 4720 / 4728 / 4732 / 4756）",
		"新建本地或域账户（中）；账户被加入 Administrators、Domain Admins、Enterprise Admins、Schema Admins、远程桌面用户、备份操作员等特权组（高）。",
		"核对是否为计划内的账号申请；否则禁用该账户、移出特权组，并排查操作者账户是否失陷。", ""},
	{model.AlertDomainAttack, "域攻击", "凭据获取", []string{"T1558.003", "T1558.004", "T1003.006", "T1550.002"}, "高 / 中",
		"Windows Agent（域控安全日志 4769 / 4768 / 4662 / 4624）",
		"Kerberoasting：同一账户 10 分钟内以 RC4 请求 3 个以上服务票据（高）；AS-REP Roasting：未启用预身份验证的账户被请求 TGT（中）；" +
			"DCSync：非域控账户请求目录复制（高）；凭据传递：以新凭据登录（LogonType 9，与 runas /netonly 相同，中）。",
		"Kerberoasting / AS-REP：重置被请求服务账户的密码并改用 AES 和强密码；DCSync：立即核查请求账户（Azure AD Connect 同步账户属正常，可标记误报），" +
			"按域失陷处理，两次重置 krbtgt 密码。", ""},
	{model.AlertAgentStopped, "Agent 被停止", "防御规避", []string{"T1562.001"}, "中", "主机 Agent",
		"Agent 收到停止信号（关机 / 重启、systemctl stop）。与「离线」（失联）区分。",
		"核对是否为计划内维护；非计划停止按可能失陷排查。", ""},
	{model.AlertAgentOffline, "Agent 离线", "防御规避", []string{"T1562.001"}, "中", "管理中心（心跳）",
		"Agent 3 分钟无心跳：宕机、网络中断，或被攻击者停止。",
		"确认主机状态；若主机在线而 Agent 被停止，按可能失陷排查。", ""},
	{model.AlertIDS, "流量入侵检测", "多阶段", []string{"依 Suricata 规则"}, "高 / 中", "探针（Suricata）",
		"Suricata 优先级 1、2 的告警；优先级 3 只记录。",
		"按规则说明处置；确认误报的在「流量检测」中添加抑制。", ""},
	{model.AlertVuln, "漏洞", "暴露面", []string{"T1190", "T1078"}, "按检查项", "探针（漏洞检测）",
		"未授权访问、弱口令、已知版本漏洞。",
		"按漏洞说明修复；修复后再跑一次漏洞检测，会自动标记为已修复。", ""},
	{model.AlertRiskyPort, "高危端口开放", "暴露面", []string{"T1133"}, "高 / 中", "探针（资产发现）",
		"新开放 telnet、Redis、数据库、RDP、SMB、Docker API 等高危端口。",
		"确认是否为业务需要；不需要的关闭，需要的限制访问来源。", ""},
	{model.AlertNewAsset, "新主机上线", "资产变化", []string{}, "中", "探针（资产发现）",
		"首次发现的主机。",
		"确认是否为已登记的设备；未知设备排查接入人和用途。", ""},
	{model.AlertNewPort, "新端口开放", "资产变化", []string{}, "低", "探针（资产发现）",
		"已知主机上新开放的端口。",
		"确认是否为预期的服务变更。", ""},
}
