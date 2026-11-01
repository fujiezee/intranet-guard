package server

import (
	_ "embed"
	htmltemplate "html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

//go:embed install/node.sh.tmpl
var nodeScriptSrc string

// upgradeGuard 是 Agent 升级保护脚本，由 Linux 安装脚本和 Kubernetes 清单写到节点上。
//
//go:embed install/upgrade-guard.sh
var upgradeGuard string

//go:embed install/agent-k8s.yaml.tmpl
var k8sManifestSrc string

var k8sManifest = template.Must(template.New("agent-k8s.yaml").Parse(k8sManifestSrc))

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
	if script == "upgrade-guard.sh" { // Kubernetes 清单的 init 容器下载它
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = io.WriteString(w, upgradeGuard)
		return
	}
	kind := map[string]string{"agent.sh": "agent", "probe.sh": "probe", "agent.ps1": "agent", "agent-k8s.yaml": "agent"}[script]
	if kind == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !validHost.MatchString(r.Host) || !validPin.MatchString(s.cfg.InstallPin) {
		writeError(w, http.StatusBadRequest, "invalid host")
		return
	}
	// 下载用本次访问的实例；写入节点配置的是全部实例（未配置 -node-urls 时即本实例）
	servers := "https://" + r.Host
	if len(s.cfg.NodeURLs) > 0 {
		servers = strings.Join(s.cfg.NodeURLs, ",")
	}
	data := map[string]string{"Kind": kind, "ServerURL": "https://" + r.Host, "Servers": servers, "Pin": s.cfg.InstallPin,
		"Guard": upgradeGuard}
	if strings.HasSuffix(script, ".yaml") {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_ = k8sManifest.Execute(w, data)
		return
	}
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
	// WindowsCommand 是 Windows Agent 的一行安装命令（PowerShell 5.1），其中 __TOKEN__、__HOSTPORT__
	// 由控制台替换为注册令牌和管理中心地址
	WindowsCommand string `json:"windows_command"`
	// NodeURLs 是配置的全部实例节点接入地址（-node-urls）；Addresses 是本机可供节点连接的地址。
	// 控制台据此给出安装命令中的默认地址：用 localhost 打开控制台时，命令里不能写 localhost。
	NodeURLs  []string `json:"node_urls"`
	Addresses []string `json:"addresses"`
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
	info := installInfo{NodePort: s.cfg.NodePort, Pin: s.cfg.InstallPin, Available: []string{},
		NodeURLs: s.cfg.NodeURLs, Addresses: []string{}}
	if info.NodeURLs == nil {
		info.NodeURLs = []string{}
	}
	for _, h := range s.cfg.NodeHosts {
		if ip, err := netip.ParseAddr(h); err == nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast()) || h == "localhost" {
			continue
		}
		info.Addresses = append(info.Addresses, h)
	}
	if validPin.MatchString(s.cfg.InstallPin) {
		info.WindowsCommand = windowsCommand("__HOSTPORT__", s.cfg.InstallPin)
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

var nodeIndexPage = htmltemplate.Must(htmltemplate.New("index").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>safe 节点接入端口</title>
<style>body{font:15px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#303133;max-width:640px;margin:60px auto;padding:0 16px}
code{background:#f5f7fa;padding:1px 5px;border-radius:3px}a{color:#409eff}</style></head><body>
<h2>这是 safe 管理中心的节点接入端口</h2>
<p>本端口供 Agent 和探针使用（双向证书认证），不是管理控制台。</p>
{{if .Console}}<p>管理控制台：<a href="{{.Console}}">{{.Console}}</a></p>{{end}}
<p>安装节点：登录控制台，在「节点管理」生成注册令牌，复制页面给出的安装命令到节点上执行。</p>
</body></html>`))

// nodeIndex：在浏览器中打开节点接入端口时，说明用途并给出控制台地址。
func (s *Server) nodeIndex(w http.ResponseWriter, r *http.Request) {
	console := ""
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if s.cfg.ConsolePort > 0 && validHost.MatchString(host) {
		console = s.cfg.ConsoleScheme + "://" + net.JoinHostPort(host, strconv.Itoa(s.cfg.ConsolePort)) + "/"
		console = strings.Replace(console, ":443/", "/", 1)
		console = strings.Replace(console, "http://"+host+":80/", "http://"+host+"/", 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = nodeIndexPage.Execute(w, map[string]string{"Console": console})
}
