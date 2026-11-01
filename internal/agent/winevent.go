package agent

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"safe/internal/model"
)

// WinEvent 是一条 Windows 事件日志记录。来自事件日志 API 渲染的 XML（字段名不随系统语言变化）。
type WinEvent struct {
	Channel  string
	Provider string
	ID       int
	RecordID uint64
	Time     time.Time
	Computer string
	Data     map[string]string // EventData 的 Data 字段；UserData 下的子元素也展开到这里
}

type xmlField struct {
	XMLName xml.Name
	Name    string `xml:"Name,attr"`
	Value   string `xml:",chardata"`
}

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int    `xml:"EventID"`
		RecordID    uint64 `xml:"EventRecordID"`
		Channel     string `xml:"Channel"`
		Computer    string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []xmlField `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []struct {
			Fields []xmlField `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
}

// ParseWinEvents 解析一段或多段 <Event> XML。
func ParseWinEvents(r io.Reader) ([]WinEvent, error) {
	dec := xml.NewDecoder(r)
	var out []WinEvent
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		} else if err != nil {
			return out, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var x xmlEvent
		if err := dec.DecodeElement(&x, &se); err != nil {
			return out, err
		}
		ev := WinEvent{Channel: x.System.Channel, Provider: x.System.Provider.Name, ID: x.System.EventID,
			RecordID: x.System.RecordID, Computer: x.System.Computer, Data: map[string]string{}}
		ev.Time, _ = time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
		for _, d := range x.EventData.Data {
			if d.Name != "" {
				ev.Data[d.Name] = strings.TrimSpace(d.Value)
			}
		}
		for _, in := range x.UserData.Inner {
			for _, f := range in.Fields {
				ev.Data[f.XMLName.Local] = strings.TrimSpace(f.Value)
			}
		}
		out = append(out, ev)
	}
}

// winIP 规范化事件中的地址字段（"-"、"::ffff:10.0.0.1" 等）。
func winIP(s string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

func isLoopback(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsLoopback()
}

// 特权组按 SID 识别（组名随系统语言变化）。域组按 RID 结尾匹配。
var privilegedSIDs = map[string]string{"S-1-5-32-544": "Administrators", "S-1-5-32-555": "Remote Desktop Users",
	"S-1-5-32-551": "Backup Operators", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators"}
var privilegedRIDs = map[string]string{"-512": "Domain Admins", "-519": "Enterprise Admins", "-518": "Schema Admins"}

func privilegedGroup(sid string) (string, bool) {
	if n, ok := privilegedSIDs[sid]; ok {
		return n, true
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		for rid, n := range privilegedRIDs {
			if strings.HasSuffix(sid, rid) {
				return n, true
			}
		}
	}
	return "", false
}

// DCSync 使用的目录复制扩展权限 GUID
var replicationGUIDs = []string{
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes-All
	"89e95b76-444d-4c62-991a-0facbeda640c", // DS-Replication-Get-Changes-In-Filtered-Set
}

var logonTypeNames = map[string]string{"2": "本地交互", "3": "网络", "4": "批处理", "5": "服务", "7": "解锁",
	"8": "网络明文", "9": "新凭据", "10": "远程桌面", "11": "缓存凭据"}

func isMachineAccount(user string) bool { return strings.HasSuffix(user, "$") }

func winUser(d map[string]string, prefix string) string {
	u := d[prefix+"UserName"]
	if dom := d[prefix+"DomainName"]; dom != "" && dom != "-" && u != "" {
		return dom + `\` + u
	}
	return u
}

const (
	kerberoastWindow    = 10 * time.Minute
	kerberoastThreshold = 3
	domainAlertQuiet    = 30 * time.Minute
)

// winDetector 把 Windows 事件转换为主机事件。Kerberoasting 需要跨事件计数，状态只保存在内存中。
type winDetector struct {
	tgs       map[string]map[string]time.Time // 请求账户 → 服务 → 最近请求时间（RC4 票据）
	lastAlert map[string]time.Time            // 同一账户同一类攻击的告警冷却
	execSeen  bool                            // 见到过进程创建事件（4688），即命令审计已生效
}

func (d *winDetector) quiet(key string, now time.Time) bool {
	if d.lastAlert == nil {
		d.lastAlert = map[string]time.Time{}
	}
	if t, ok := d.lastAlert[key]; ok && now.Sub(t) < domainAlertQuiet {
		return true
	}
	d.lastAlert[key] = now
	return false
}

// Evaluate 返回事件对应的主机事件（可能为空）。
func (d *winDetector) Evaluate(ev WinEvent) []model.HostEvent {
	data := ev.Data
	t := ev.Time
	if t.IsZero() {
		t = time.Now()
	}
	he := func(typ model.HostEventType, sev, detail string) model.HostEvent {
		return model.HostEvent{Type: typ, Time: t, Severity: sev, Detail: detail}
	}
	switch {
	case ev.Channel == "Security" && ev.ID == 4625: // 登录失败
		e := he(model.EventLoginFailed, "", fmt.Sprintf("Windows 登录失败（%s登录，状态 %s/%s）",
			logonTypeNames[data["LogonType"]], data["Status"], data["SubStatus"]))
		e.User, e.SrcIP = winUser(data, "Target"), winIP(data["IpAddress"])
		return []model.HostEvent{e}

	case ev.Channel == "Security" && ev.ID == 4624: // 登录成功
		user := data["TargetUserName"]
		if isMachineAccount(user) || strings.EqualFold(user, "ANONYMOUS LOGON") {
			return nil
		}
		if data["LogonType"] == "9" && strings.EqualFold(data["LogonProcessName"], "seclogo") {
			e := he(model.EventDomainAttack, "medium", fmt.Sprintf("[凭据传递] %s 以新凭据（LogonType 9）启动进程 %s；"+
				"mimikatz 的 pass-the-hash 与 runas /netonly 产生相同记录，请核实", winUser(data, "Subject"), data["ProcessName"]))
			e.User = winUser(data, "Subject")
			return []model.HostEvent{e}
		}
		ip := winIP(data["IpAddress"])
		if ip == "" || isLoopback(ip) {
			return nil
		}
		// 只上报远程桌面和 NTLM 网络登录：Kerberos 网络登录（访问共享等）是域内的正常流量，数量极大
		var detail string
		switch {
		case data["LogonType"] == "10":
			detail = "远程桌面登录"
		case data["LogonType"] == "3" && strings.EqualFold(data["AuthenticationPackageName"], "NTLM"):
			detail = "NTLM 网络登录（" + data["LmPackageName"] + "）"
		default:
			return nil
		}
		e := he(model.EventLoginSuccess, "", detail)
		e.User, e.SrcIP = winUser(data, "Target"), ip
		return []model.HostEvent{e}

	case ev.Channel == "Security" && ev.ID == 4688: // 进程创建
		d.execSeen = true
		image, cmdline, parent := data["NewProcessName"], data["CommandLine"], data["ParentProcessName"]
		var out []model.HostEvent
		for _, f := range EvaluateWinCommand(image, cmdline, parent) {
			c := cmdline
			if c == "" {
				c = image + "（未开启命令行审计）"
			}
			e := he(model.EventSuspiciousCommand, f.Severity, fmt.Sprintf("[%s] %s；命令：%s；父进程：%s", f.Name, f.Reason, c, parent))
			e.User, e.Path = winUser(data, "Subject"), image
			out = append(out, e)
		}
		return out

	case ev.Channel == "Security" && ev.ID == 4720: // 新建账户
		e := he(model.EventAccountChange, "medium", fmt.Sprintf("新建账户 %s（操作者 %s）", winUser(data, "Target"), winUser(data, "Subject")))
		e.User = winUser(data, "Subject")
		return []model.HostEvent{e}

	case ev.Channel == "Security" && (ev.ID == 4728 || ev.ID == 4732 || ev.ID == 4756): // 加入安全组
		group, ok := privilegedGroup(data["TargetSid"])
		if !ok {
			return nil
		}
		member := data["MemberName"]
		if member == "" || member == "-" {
			member = data["MemberSid"]
		}
		e := he(model.EventAccountChange, "high", fmt.Sprintf("%s 被加入特权组 %s（%s，操作者 %s）",
			member, group, winUser(data, "Target"), winUser(data, "Subject")))
		e.User = winUser(data, "Subject")
		return []model.HostEvent{e}

	case ev.Channel == "Security" && ev.ID == 1102, ev.Channel == "System" && ev.ID == 104 && strings.Contains(ev.Provider, "Eventlog"):
		log := data["Channel"]
		if log == "" {
			log = "Security"
		}
		e := he(model.EventSuspiciousCommand, "high", fmt.Sprintf("[清除日志] 事件日志 %s 被 %s 清除", log, winUser(data, "Subject")))
		e.User = winUser(data, "Subject")
		return []model.HostEvent{e}

	case ev.Channel == "System" && ev.ID == 7045: // 安装服务
		name, image := data["ServiceName"], data["ImagePath"]
		if reason := suspiciousService(name, image); reason != "" {
			return []model.HostEvent{he(model.EventSuspiciousCommand, "high",
				fmt.Sprintf("[可疑服务] 新安装服务 %s：%s；程序 %s（账户 %s）", name, reason, image, data["AccountName"]))}
		}
		return []model.HostEvent{he(model.EventCommand, "", fmt.Sprintf("新安装服务 %s：%s", name, image))}

	case ev.Channel == "Security" && ev.ID == 4769: // Kerberos 服务票据
		return d.kerberoast(ev, t)

	case ev.Channel == "Security" && ev.ID == 4768: // Kerberos TGT
		if data["PreAuthType"] != "0" || data["Status"] != "0x0" || isMachineAccount(data["TargetUserName"]) {
			return nil
		}
		acct := data["TargetUserName"]
		if d.quiet("asrep:"+acct, t) {
			return nil
		}
		e := he(model.EventDomainAttack, "medium", fmt.Sprintf("[AS-REP Roasting] 账户 %s 未启用 Kerberos 预身份验证，被请求了 TGT（可离线破解其密码）", acct))
		e.SrcIP = winIP(data["IpAddress"])
		return []model.HostEvent{e}

	case ev.Channel == "Security" && ev.ID == 4662: // 目录服务对象访问
		props := strings.ToLower(data["Properties"])
		subject := data["SubjectUserName"]
		if isMachineAccount(subject) {
			return nil // 域控之间的正常复制
		}
		for _, g := range replicationGUIDs {
			if strings.Contains(props, g) {
				if d.quiet("dcsync:"+subject, t) {
					return nil
				}
				e := he(model.EventDomainAttack, "high", fmt.Sprintf("[DCSync] 非域控账户 %s 请求目录复制，可导出全部账户的密码哈希", winUser(data, "Subject")))
				e.User = winUser(data, "Subject")
				return []model.HostEvent{e}
			}
		}
	}
	return nil
}

// kerberoast：同一账户短时间内以 RC4 请求多个服务账户的票据。单次 RC4 请求在老系统上可能是正常的。
func (d *winDetector) kerberoast(ev WinEvent, t time.Time) []model.HostEvent {
	data := ev.Data
	svc, enc := data["ServiceName"], strings.ToLower(data["TicketEncryptionType"])
	if (enc != "0x17" && enc != "0x18") || data["Status"] != "0x0" || isMachineAccount(svc) || strings.EqualFold(svc, "krbtgt") {
		return nil
	}
	acct := data["TargetUserName"]
	if d.tgs == nil {
		d.tgs = map[string]map[string]time.Time{}
	}
	if d.tgs[acct] == nil {
		d.tgs[acct] = map[string]time.Time{}
	}
	d.tgs[acct][svc] = t
	var services []string
	for s, at := range d.tgs[acct] {
		if t.Sub(at) > kerberoastWindow {
			delete(d.tgs[acct], s)
			continue
		}
		services = append(services, s)
	}
	if len(services) < kerberoastThreshold || d.quiet("kerberoast:"+acct, t) {
		return nil
	}
	sort.Strings(services)
	e := model.HostEvent{Type: model.EventDomainAttack, Time: t, Severity: "high", User: acct, SrcIP: winIP(data["IpAddress"]),
		Detail: fmt.Sprintf("[Kerberoasting] 账户 %s 在 %d 分钟内以 RC4 加密请求了 %d 个服务的票据：%s",
			acct, int(kerberoastWindow.Minutes()), len(services), strings.Join(services, "、"))}
	return []model.HostEvent{e}
}

// suspiciousService 判断新安装的服务是否可疑：远程执行工具、用 cmd / PowerShell 启动、程序放在临时或用户目录。
func suspiciousService(name, image string) string {
	img := strings.ToLower(image)
	switch {
	case strings.EqualFold(name, "PSEXESVC") || strings.Contains(img, "psexesvc"):
		return "PsExec 远程执行"
	case strings.Contains(img, "cmd.exe") || strings.Contains(img, "cmd /c") || strings.Contains(img, "%comspec%"):
		return "通过 cmd 执行命令（impacket smbexec / 远程执行常见）"
	case strings.Contains(img, "powershell") || strings.Contains(img, "pwsh"):
		return "通过 PowerShell 执行"
	case strings.Contains(img, "mshta") || strings.Contains(img, "rundll32") || strings.Contains(img, "regsvr32"):
		return "通过系统程序代理执行"
	case strings.HasPrefix(img, `\\`):
		return "程序位于网络共享"
	case strings.Contains(img, `\temp\`) || strings.Contains(img, `\appdata\`) || strings.Contains(img, `\users\public\`):
		return "程序位于临时或用户目录"
	}
	return ""
}
