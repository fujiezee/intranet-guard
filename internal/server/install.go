package server

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"text/template"
)

//go:embed install/node.sh.tmpl
var nodeScriptSrc string

var nodeScript = template.Must(template.New("node.sh").Parse(nodeScriptSrc))

var (
	// 地址和指纹会被写进 shell 脚本的单引号字符串里，必须严格校验，防止注入。
	validHost = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)
	validPin  = regexp.MustCompile(`^sha256//[A-Za-z0-9+/=]{44}$`)
	validDist = regexp.MustCompile(`^safe-(agent|probe)-linux-(amd64|arm64)$`)
)

// installScript 返回节点一键安装脚本。脚本里的管理中心地址取自请求的 Host：
// 节点用什么地址下载脚本，之后就用同一地址连接管理中心。
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	kind := map[string]string{"agent.sh": "agent", "probe.sh": "probe"}[r.PathValue("script")]
	if kind == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !validHost.MatchString(r.Host) || !validPin.MatchString(s.cfg.InstallPin) {
		writeError(w, http.StatusBadRequest, "invalid host")
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_ = nodeScript.Execute(w, map[string]string{"Kind": kind, "ServerURL": "https://" + r.Host, "Pin": s.cfg.InstallPin})
}

// download 提供节点程序下载（来自安装包中的 downloads 目录），只允许固定的文件名。
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !validDist.MatchString(name) || s.cfg.DistDir == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	path := filepath.Join(s.cfg.DistDir, name)
	if _, err := os.Stat(path); err != nil {
		writeError(w, http.StatusNotFound, "binary not available on this server: "+name)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

type installInfo struct {
	NodePort  int      `json:"node_port"`
	Pin       string   `json:"pin"`
	Available []string `json:"available"` // 可下载的节点程序
}

// installInfoHandler 供控制台拼出一键安装命令。
func (s *Server) installInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := installInfo{NodePort: s.cfg.NodePort, Pin: s.cfg.InstallPin, Available: []string{}}
	if s.cfg.DistDir != "" {
		entries, _ := os.ReadDir(s.cfg.DistDir)
		for _, e := range entries {
			if validDist.MatchString(e.Name()) {
				info.Available = append(info.Available, e.Name())
			}
		}
	}
	writeJSON(w, http.StatusOK, info)
}
