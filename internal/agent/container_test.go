package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCgroup(t *testing.T) {
	id := "3f5a0e1c2b4d6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"
	uid := "0d6f1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b"
	for name, tc := range map[string]struct {
		cgroup     string
		id, podUID string
	}{
		"v2 systemd containerd": {"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" +
			strings.ReplaceAll(uid, "-", "_") + ".slice/cri-containerd-" + id + ".scope\n", id[:12], uid},
		"v2 cgroupfs (k3s)": {"0::/kubepods/besteffort/pod" + uid + "/" + id + "\n", id[:12], uid},
		"v1 docker":         {"12:memory:/docker/" + id + "\n11:cpu,cpuacct:/docker/" + id + "\n", id[:12], ""},
		"v2 docker systemd": {"0::/system.slice/docker-" + id + ".scope\n", id[:12], ""},
		"host process":      {"0::/user.slice/user-1000.slice/session-3.scope\n", "", ""},
		"host service":      {"0::/system.slice/sshd.service\n", "", ""},
	} {
		c := ParseCgroup(tc.cgroup)
		if c.ID != tc.id || c.PodUID != tc.podUID {
			t.Errorf("%s: got %+v", name, c)
		}
	}
}

func TestPodIndex(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "shop_web-7d9f8-abcde_0d6f1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b"), 0o755)
	p := newPodIndex(dir)
	c := p.resolve(Container{ID: "3f5a0e1c2b4d", PodUID: "0d6f1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b"})
	if c.Namespace != "shop" || c.Pod != "web-7d9f8-abcde" || c.String() != "Pod shop/web-7d9f8-abcde（容器 3f5a0e1c2b4d）" {
		t.Errorf("resolved: %+v %q", c, c.String())
	}
	if c := p.resolve(Container{ID: "aaaaaaaaaaaa", PodUID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}); c.Pod != "" || c.String() != "容器 aaaaaaaaaaaa" {
		t.Errorf("unknown pod: %+v", c)
	}
}

func TestContainerRules(t *testing.T) {
	in := Container{ID: "3f5a0e1c2b4d"}
	has := func(e ExecInfo, rule string) bool {
		for _, f := range EvaluateExec(e) {
			if f.Rule == rule {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		e    ExecInfo
		rule string
		want bool
	}{
		{ExecInfo{Comm: "sh", Exe: "/bin/busybox", TTY: true, Container: in}, "container_shell", true},
		{ExecInfo{Comm: "bash", Exe: "/bin/bash", TTY: true}, "container_shell", false}, // 宿主机上的交互 shell
		{ExecInfo{Comm: "sh", Exe: "/bin/sh", Container: in, Cmdline: "sh -c /app/start.sh"}, "container_shell", false},
		{ExecInfo{Comm: "nsenter", Container: in, Cmdline: "nsenter -t 1 -m -u -i -n sh"}, "container_escape", true},
		{ExecInfo{Comm: "nsenter", Container: in, Cmdline: "nsenter --target=1 --mount sh"}, "container_escape", true},
		{ExecInfo{Comm: "mount", Container: in, Cmdline: "mount /dev/vda1 /mnt"}, "container_escape", true},
		{ExecInfo{Comm: "sh", Container: in, Cmdline: "sh -c echo /x > /tmp/cg/release_agent"}, "container_escape", true},
		{ExecInfo{Comm: "curl", Container: in, Cmdline: "curl --unix-socket /var/run/docker.sock http://x/containers/json"}, "container_runtime_socket", true},
		{ExecInfo{Comm: "cat", Container: in, Cmdline: "cat /var/run/secrets/kubernetes.io/serviceaccount/token"}, "k8s_token_access", true},
		{ExecInfo{Comm: "curl", Container: in, Cmdline: "curl -k https://kubernetes.default.svc/api/v1/secrets"}, "k8s_token_access", true},
		{ExecInfo{Comm: "kubectl", Container: in, Cmdline: "kubectl apply -f /chart/crd.yaml"}, "k8s_token_access", false},
		{ExecInfo{Comm: "mount", Cmdline: "mount /dev/vda1 /mnt"}, "container_escape", false}, // 宿主机上挂载磁盘是运维操作
	} {
		if got := has(tc.e, tc.rule); got != tc.want {
			t.Errorf("%s on %+v: got %v want %v", tc.rule, tc.e, got, tc.want)
		}
	}
}
