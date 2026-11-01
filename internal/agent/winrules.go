package agent

import (
	"encoding/base64"
	"path"
	"regexp"
	"strings"
	"unicode/utf16"
)

// Windows 进程创建（安全日志 4688）的检测规则。输入为程序路径、命令行和父进程路径。

func winBase(p string) string {
	return strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
}

var (
	// PowerShell 接受 -EncodedCommand 的任意无歧义前缀：-e、-ec、-enc、-encodedcommand……
	reWinEncoded = regexp.MustCompile(`(?i)(?:^|\s)[-/](?:e|ec|en[a-z]*)\s+([a-z0-9+/=]{16,})`)
	reWinCradle  = regexp.MustCompile(`(?i)(?:\biex\b|invoke-expression).*(?:downloadstring|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer)` +
		`|(?:downloadstring|downloadfile)\s*\(\s*['"]https?://` +
		`|(?:\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod)\s.*https?://.*\|\s*(?:\biex\b|invoke-expression)`)
	reWinLOLBin = regexp.MustCompile(`(?i)certutil(?:\.exe)?\s.*-urlcache.*https?://|bitsadmin(?:\.exe)?\s.*/transfer` +
		`|mshta(?:\.exe)?\s+["']?(?:https?:|vbscript:|javascript:)|regsvr32(?:\.exe)?\s.*/i:https?://|rundll32(?:\.exe)?\s.*javascript:`)
	reWinBackupWipe = regexp.MustCompile(`(?i)vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s.*shadowcopy\s+delete` +
		`|bcdedit(?:\.exe)?\s.*recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)`)
	reWinLogClear = regexp.MustCompile(`(?i)wevtutil(?:\.exe)?\s+(?:cl|clear-log)\s|clear-eventlog|remove-eventlog`)
	// 凭据窃取工具的特征字符串拆开拼接：避免 Agent 程序本身因包含这些字符串被杀毒软件误判为黑客工具
	reWinCredDump = regexp.MustCompile(`(?i)` + "sekur" + "lsa::|" + "lsa" + "dump::|" + "mimi" + "katz" +
		`|procdump(?:64)?(?:\.exe)?\s.*\blsass|comsvcs(?:\.dll)?[,\s].*minidump|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|security|system)\b|ntdsutil.*\bifm\b`)
)

var winShells = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true}

// Web / 数据库服务派生的命令（Webshell、xp_cmdshell 之后的典型动作）
var winServerParents = map[string]bool{"w3wp.exe": true, "httpd.exe": true, "nginx.exe": true, "php-cgi.exe": true,
	"sqlservr.exe": true, "tomcat.exe": true, "tomcat8.exe": true, "tomcat9.exe": true, "tomcat10.exe": true}
var winReconAndShell = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "whoami.exe": true,
	"net.exe": true, "net1.exe": true, "ipconfig.exe": true, "systeminfo.exe": true, "certutil.exe": true, "bitsadmin.exe": true,
	"wmic.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true, "cscript.exe": true, "wscript.exe": true,
	"tasklist.exe": true, "quser.exe": true, "nltest.exe": true, "netstat.exe": true}

// Office / WPS 派生脚本解释器：宏病毒的典型行为
var winOffice = map[string]bool{"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true,
	"wps.exe": true, "et.exe": true, "wpp.exe": true}
var winScriptHosts = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "mshta.exe": true,
	"wscript.exe": true, "cscript.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true, "bitsadmin.exe": true}

// decodePSEncoded 解码 -EncodedCommand 的参数（UTF-16LE 的 Base64）。
func decodePSEncoded(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// EvaluateWinCommand 返回一次 Windows 进程创建命中的规则。
func EvaluateWinCommand(image, cmdline, parentImage string) []CmdFinding {
	var out []CmdFinding
	add := func(rule, name, sev, reason string) {
		out = append(out, CmdFinding{Rule: rule, Name: name, Severity: sev, Reason: reason})
	}
	img, parent := winBase(image), winBase(parentImage)

	if (img == "powershell.exe" || img == "pwsh.exe") && cmdline != "" {
		if m := reWinEncoded.FindStringSubmatch(cmdline); m != nil {
			decoded := decodePSEncoded(m[1])
			if reWinCradle.MatchString(decoded) {
				add("win_download_exec", "下载并执行", "high", "编码的 PowerShell 命令解码后为下载执行："+truncate(decoded, 200))
			} else {
				add("win_encoded_ps", "编码的 PowerShell", "medium", "使用 -EncodedCommand 隐藏命令内容，解码后："+truncate(decoded, 200))
			}
		}
	}
	switch {
	case reWinCradle.MatchString(cmdline):
		add("win_download_exec", "下载并执行", "high", "PowerShell 下载远程脚本并直接执行")
	case reWinLOLBin.MatchString(cmdline):
		add("win_lolbin", "系统程序下载 / 代理执行", "high", "利用 certutil、bitsadmin、mshta、regsvr32、rundll32 等系统程序下载或执行远程代码")
	}
	if reWinBackupWipe.MatchString(cmdline) {
		add("win_backup_wipe", "破坏备份", "high", "删除卷影副本或系统备份、关闭恢复，勒索软件加密前的典型动作")
	}
	if reWinLogClear.MatchString(cmdline) {
		add("win_log_clear", "清除日志", "high", "清除 Windows 事件日志，掩盖入侵痕迹")
	}
	if reWinCredDump.MatchString(cmdline) {
		add("win_cred_dump", "凭据窃取", "high", "读取 LSASS 内存、导出 SAM / NTDS 或使用凭据窃取工具")
	}
	if winServerParents[parent] && winReconAndShell[img] {
		add("win_server_spawn", "服务进程派生命令", "high", parent+" 启动了 "+img+"（Webshell 或数据库命令执行的迹象）")
	} else if winOffice[parent] && winScriptHosts[img] {
		add("win_office_spawn", "Office 派生命令", "high", parent+" 启动了 "+img+"（恶意宏的典型行为）")
	} else if parent == "java.exe" && winShells[img] {
		add("win_app_spawn", "应用服务派生 shell", "medium", "java.exe 启动了 "+img+"（可能是正常的运维调用）")
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
