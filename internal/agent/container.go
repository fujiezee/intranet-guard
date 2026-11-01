package agent

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// 容器识别：从 /proc/<pid>/cgroup 取容器 ID 和 Pod UID，再按 /var/log/pods/<命名空间>_<Pod 名>_<UID> 的目录名
// 找到 Pod。不访问 Kubernetes API，因此不需要 ServiceAccount 权限，Docker / containerd / CRI-O、
// cgroup v1 / v2、systemd / cgroupfs 驱动都适用。
var (
	cgroupContainerID = regexp.MustCompile(`([0-9a-f]{64})(?:\.scope)?\s*$`)
	cgroupPodUID      = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
)

// Container 描述进程所在的容器；不在容器中时为零值。
type Container struct {
	ID        string // 容器 ID 前 12 位
	PodUID    string
	Namespace string
	Pod       string
}

func (c Container) String() string {
	switch {
	case c.Pod != "":
		return "Pod " + c.Namespace + "/" + c.Pod + "（容器 " + c.ID + "）"
	case c.ID != "":
		return "容器 " + c.ID
	}
	return ""
}

// ParseCgroup 从 /proc/<pid>/cgroup 的内容中取容器 ID 和 Pod UID。
func ParseCgroup(content string) Container {
	var c Container
	for _, line := range strings.Split(content, "\n") {
		// 格式 层级:控制器:路径，取最后一段路径
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if m := cgroupContainerID.FindStringSubmatch(path); m != nil && c.ID == "" {
			c.ID = m[1][:12]
		}
		if m := cgroupPodUID.FindStringSubmatch(path); m != nil && c.PodUID == "" {
			c.PodUID = strings.ReplaceAll(m[1], "_", "-")
		}
	}
	return c
}

// podIndex 缓存 Pod UID → 命名空间 / 名称，未命中时最多每 10 秒重新读取一次目录。
type podIndex struct {
	dir    string
	mu     sync.Mutex
	byUID  map[string][2]string
	loaded time.Time
}

func newPodIndex(dir string) *podIndex { return &podIndex{dir: dir, byUID: map[string][2]string{}} }

func (p *podIndex) lookup(uid string) (ns, name string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.byUID[uid]; ok {
		return v[0], v[1], true
	}
	if time.Since(p.loaded) < 10*time.Second {
		return "", "", false
	}
	p.loaded = time.Now()
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return "", "", false
	}
	p.byUID = map[string][2]string{}
	for _, e := range entries {
		// <命名空间>_<Pod 名>_<UID>：命名空间和 Pod 名不含下划线（DNS-1123），UID 不含下划线
		f := strings.Split(e.Name(), "_")
		if len(f) == 3 {
			p.byUID[f[2]] = [2]string{f[0], f[1]}
		}
	}
	v, ok := p.byUID[uid]
	return v[0], v[1], ok
}

func (p *podIndex) resolve(c Container) Container {
	if c.PodUID != "" {
		if ns, name, ok := p.lookup(c.PodUID); ok {
			c.Namespace, c.Pod = ns, name
		}
	}
	return c
}
