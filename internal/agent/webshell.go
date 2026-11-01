package agent

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"safe/internal/model"
)

// DefaultWebDirs 是常见的网站目录；不存在的目录自动跳过。
var DefaultWebDirs = []string{"/var/www", "/usr/share/nginx/html", "/srv/www", "/opt/tomcat/webapps", "/usr/local/tomcat/webapps"}

var webScriptExt = map[string]bool{".php": true, ".php5": true, ".phtml": true, ".jsp": true, ".jspx": true,
	".asp": true, ".aspx": true, ".ashx": true}

const (
	maxWebFiles     = 20000     // 单台主机最多跟踪的脚本文件数
	maxWebshellRead = 512 << 10 // 每个文件最多检查的字节数
)

// 常见 Webshell 特征：动态执行、编码混淆、命令执行。正常业务代码也可能包含个别函数，因此只提高级别，不单独判定。
var webshellFeatures = []struct {
	name string
	re   *regexp.Regexp
}{
	{"eval", regexp.MustCompile(`(?i)\beval\s*\(`)},
	{"assert", regexp.MustCompile(`(?i)\bassert\s*\(\s*\$`)},
	{"编码混淆", regexp.MustCompile(`(?i)\b(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(`)},
	{"命令执行", regexp.MustCompile(`(?i)\b(system|passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\(`)},
	{"Java 命令执行", regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder`)},
	{"动态类加载", regexp.MustCompile(`defineClass|ClassLoader.*\.newInstance`)},
	{"请求参数直接执行", regexp.MustCompile(`(?i)\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\)`)},
}

// scanWebDirs 记录网站目录中脚本文件的大小和修改时间。
func scanWebDirs(dirs []string) map[string]FileInfo {
	out := map[string]FileInfo{}
	for _, root := range dirs {
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || len(out) >= maxWebFiles {
				return filepath.SkipDir
			}
			if d.IsDir() || !webScriptExt[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				out[path] = FileInfo{Size: info.Size(), Mod: info.ModTime().UTC()}
			}
			return nil
		})
	}
	return out
}

// diffWebFiles 对新增或修改的脚本文件检查 Webshell 特征。
func diffWebFiles(old, cur map[string]FileInfo, now time.Time) []model.HostEvent {
	var events []model.HostEvent
	for path, c := range cur {
		o, existed := old[path]
		if existed && o.Size == c.Size && o.Mod.Equal(c.Mod) {
			continue
		}
		features := webshellFeaturesOf(path)
		action := "新增脚本文件"
		if existed {
			action = "脚本文件被修改"
		}
		detail := action
		sev := "medium"
		if len(features) > 0 {
			detail += "，含 Webshell 特征：" + strings.Join(features, "、")
			sev = "high"
		}
		events = append(events, model.HostEvent{Type: model.EventWebshell, Time: now, Path: path, Detail: detail, Severity: sev})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Path < events[j].Path })
	return events
}

func webshellFeaturesOf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxWebshellRead))
	var out []string
	for _, ft := range webshellFeatures {
		if ft.re.Match(b) {
			out = append(out, ft.name)
		}
	}
	return out
}
