package server

import (
	_ "embed"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

//go:embed install/node.sh.tmpl
var nodeScriptSrc string

//go:embed install/agent.ps1.tmpl
var winScriptSrc string

var (
	nodeScript = template.Must(template.New("node.sh").Parse(nodeScriptSrc))
	winScript  = template.Must(template.New("agent.ps1").Parse(winScriptSrc))
)

var (
	// 地址和指纹会被写进 shell 脚本的单引号字符串里，必须严格校验，防止注入。
	validHost = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)
	validPin  = regexp.MustCompile(`^sha256//[A-Za-z0-9+/=]{44}$`)
	validDist = regexp.MustCompile(`^safe-(agent|probe)-linux-(amd64|arm64)$|^safe-agent-windows-(amd64|arm64)\.exe$`)
)

// installScript 返回节点一键安装脚本。脚本里的管理中心地址取自请求的 Host：
// 节点用什么地址下载脚本，之后就用同一地址连接管理中心。
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	script := r.PathValue("script")
	kind := map[string]string{"agent.sh": "agent", "probe.sh": "probe", "agent.ps1": "agent"}[script]
	if kind == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !validHost.MatchString(r.Host) || !validPin.MatchString(s.cfg.InstallPin) {
		writeError(w, http.StatusBadRequest, "invalid host")
		return
	}
	data := map[string]string{"Kind": kind, "ServerURL": "https://" + r.Host, "Pin": s.cfg.InstallPin}
	if strings.HasSuffix(script, ".ps1") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_ = winScript.Execute(w, data)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_ = nodeScript.Execute(w, data)
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
	// WindowsCommand 是 Windows Agent 的一行安装命令（PowerShell 5.1），其中 __TOKEN__ 由控制台替换为注册令牌
	WindowsCommand string `json:"windows_command"`
}

// P-256 公钥的 SubjectPublicKeyInfo 固定前缀：PowerShell 5.1 只能取得证书的原始公钥，
// 加上前缀后计算的 SHA-256 与 curl --pinnedpubkey 的指纹相同。
const p256SPKIPrefix = "0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00"

// windowsCommand 生成 Windows 一行安装命令：先固定管理中心公钥（替换证书校验），再下载并执行安装脚本。
func windowsCommand(serverHost, pin string) string {
	return "$env:SAFE_ENROLL_TOKEN='__TOKEN__'; " +
		"[Net.ServicePointManager]::SecurityProtocol='Tls12'; " +
		"[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c)" +
		"[Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash([byte[]](@(" + p256SPKIPrefix + ")+$c.GetPublicKey()))) -eq '" +
		strings.TrimPrefix(pin, "sha256//") + "'}; " +
		"$w=New-Object Net.WebClient; $w.Encoding=[Text.Encoding]::UTF8; " +
		"iex $w.DownloadString('https://" + serverHost + "/install/agent.ps1')"
}

// installInfoHandler 供控制台拼出一键安装命令。
func (s *Server) installInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := installInfo{NodePort: s.cfg.NodePort, Pin: s.cfg.InstallPin, Available: []string{}}
	// 节点用浏览器访问控制台时的主机名连接管理中心（与 Linux 命令的生成方式一致）
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if hp := net.JoinHostPort(host, strconv.Itoa(s.cfg.NodePort)); validHost.MatchString(hp) && validPin.MatchString(s.cfg.InstallPin) {
		info.WindowsCommand = windowsCommand(hp, s.cfg.InstallPin)
	}
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
