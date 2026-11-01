package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"safe/internal/model"
)

// DefaultFIMPaths 是 Linux 上常被攻击者篡改以维持权限或提权的文件。
// 目录只监控第一层的普通文件；支持通配符。
var DefaultFIMPaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/sudoers", "/etc/sudoers.d",
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys",
	"/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron",
	"/etc/ld.so.preload", "/etc/hosts", "/etc/pam.d",
	"/etc/systemd/system", "/etc/rc.local", "/etc/profile", "/etc/profile.d",
}

const maxHashSize = 64 << 20 // 超过这个大小的文件只比较大小和修改时间

type FileInfo struct {
	Hash string    `json:"hash"`
	Size int64     `json:"size"`
	Mode string    `json:"mode"`
	Mod  time.Time `json:"mod"`
}

// ScanFiles 计算受监控路径下所有文件的指纹。
func ScanFiles(patterns []string) map[string]FileInfo {
	out := map[string]FileInfo{}
	for _, pat := range patterns {
		// 不存在的路径也保留在列表里：之后被创建（如 /etc/ld.so.preload）会产生 created 事件。
		matches, _ := filepath.Glob(pat)
		for _, p := range matches {
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				addFile(out, p, fi)
				continue
			}
			entries, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, e := range entries {
				child := filepath.Join(p, e.Name())
				if cfi, err := os.Lstat(child); err == nil && !cfi.IsDir() {
					addFile(out, child, cfi)
				}
			}
		}
	}
	return out
}

func addFile(out map[string]FileInfo, path string, fi os.FileInfo) {
	info := FileInfo{Size: fi.Size(), Mode: fi.Mode().String(), Mod: fi.ModTime().UTC()}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		info.Hash = "link:" + target
	case fi.Mode().IsRegular() && fi.Size() <= maxHashSize:
		if h, err := hashFile(path); err == nil {
			info.Hash = h
		}
	}
	out[path] = info
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// DiffFiles 比较两次扫描结果，生成新增、修改、删除事件。
func DiffFiles(old, cur map[string]FileInfo, now time.Time) []model.HostEvent {
	var events []model.HostEvent
	add := func(path, detail string) {
		events = append(events, model.HostEvent{Type: model.EventFileChanged, Time: now, Path: path, Detail: detail})
	}
	for path, c := range cur {
		o, ok := old[path]
		switch {
		case !ok:
			add(path, "created")
		case o.Hash != c.Hash || (c.Hash == "" && (o.Size != c.Size || !o.Mod.Equal(c.Mod))):
			add(path, fmt.Sprintf("modified (size %d -> %d)", o.Size, c.Size))
		case o.Mode != c.Mode:
			add(path, fmt.Sprintf("permissions changed (%s -> %s)", o.Mode, c.Mode))
		}
	}
	for path := range old {
		if _, ok := cur[path]; !ok {
			add(path, "deleted")
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Path < events[j].Path })
	return events
}
