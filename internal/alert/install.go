package alert

import (
	"regexp"
	"strings"
)

// installCommandDetail 匹配 Agent 上报的"下载并执行"事件详情：[下载并执行] 命令匹配特征；命令：<命令行>；父进程：<父进程>…
var installCommandDetail = regexp.MustCompile(`^\[下载并执行\] 命令匹配特征；命令：(.+)；父进程：[^；]*(；位置：.*)?$`)

// IsInstallCommand 判断一条"下载并执行"事件是否只是在执行本管理中心给出的一键安装命令：
// curl 固定了本管理中心的公钥指纹（-k 下只有真正的管理中心能通过，下载到的只能是它的安装脚本），
// 地址是安装脚本，管道后只有 sh（可带 sudo 和 SAFE_* 变量），没有拼接其他命令。
// 交互式终端里输入的管道不会产生这样的命令行，常见于 ssh 远程执行、Ansible 等批量下发。
func IsInstallCommand(detail, pin string) bool {
	if pin == "" {
		return false
	}
	m := installCommandDetail.FindStringSubmatch(detail)
	if m == nil {
		return false
	}
	return installCommandLine(pin).MatchString(strings.TrimSpace(m[1]))
}

func installCommandLine(pin string) *regexp.Regexp {
	q := func(s string) string { return `['"]?` + s + `['"]?` }
	value := `(?:'[A-Za-z0-9._-]*'|"[A-Za-z0-9._-]*"|[A-Za-z0-9._-]+)`
	return regexp.MustCompile(`^(?:(?:ba|da)?sh -c )?curl -fsSLk --pinnedpubkey ` + q(regexp.QuoteMeta(pin)) + ` ` +
		q(`https://[A-Za-z0-9.\-]+(?::[0-9]{1,5})?/(?:install/(?:agent|probe)\.sh|i/[0-9a-f]{32}\.[0-9a-f]{64}(?:\?id=[A-Za-z0-9._-]+)?)`) +
		` \| (?:sudo )?(?:SAFE_[A-Z_]+=` + value + ` )*(?:ba|da)?sh$`)
}
