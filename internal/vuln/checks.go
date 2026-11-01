// Package vuln 实现漏洞检测：探针侧的网络检查（未授权访问、弱口令）和管理中心侧的 Banner 版本匹配。
package vuln

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"safe/internal/model"
)

type Options struct {
	WeakPassword bool          // 是否尝试弱口令
	Timeout      time.Duration // 单次连接 / 读写超时
	Concurrency  int           // 同时检查的主机数；同一主机上的检查串行执行，避免触发锁定
	AttemptDelay time.Duration // 同一主机两次登录尝试之间的间隔
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 32
	}
	if o.AttemptDelay <= 0 {
		o.AttemptDelay = 300 * time.Millisecond
	}
}

// Credential 是弱口令字典中的一组账号密码。
type Credential struct{ User, Pass string }

// 字典刻意保持很小：每台主机每个服务的失败次数低于常见锁定 / 爆破告警阈值（本系统为 10 次）。
var (
	SSHCredentials = []Credential{
		{"root", "root"}, {"root", "123456"}, {"root", "password"}, {"root", "toor"},
		{"admin", "admin"}, {"admin", "123456"}, {"test", "test"}, {"oracle", "oracle"},
	}
	FTPCredentials = []Credential{
		{"ftp", "ftp"}, {"admin", "admin"}, {"admin", "123456"}, {"test", "test"}, {"root", "root"},
	}
	RedisPasswords = []string{"123456", "redis", "password", "admin", "foobared"}
)

type check struct {
	id    string
	match func(model.Port) bool
	run   func(ctx context.Context, addr string, opts Options) []model.CheckResult
}

func byPortOrService(port int, service string) func(model.Port) bool {
	return func(p model.Port) bool { return p.Port == port || p.Service == service }
}

var checks = []check{
	{"redis", byPortOrService(6379, "redis"), checkRedis},
	{"memcached-unauth", byPortOrService(11211, "memcached"), checkMemcached},
	{"elasticsearch-unauth", byPortOrService(9200, "elasticsearch"), checkElasticsearch},
	{"docker-api-unauth", byPortOrService(2375, "docker"), checkDockerAPI},
	{"ftp", byPortOrService(21, "ftp"), checkFTP},
	{"ssh-weak-password", byPortOrService(22, "ssh"), checkSSH},
}

// Run 对已发现的开放端口执行适用的检查。
func Run(ctx context.Context, assets []model.Asset, opts Options) []model.CheckResult {
	opts.defaults()
	var (
		mu      sync.Mutex
		results []model.CheckResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, opts.Concurrency)
	)
	for _, a := range assets {
		wg.Add(1)
		go func(a model.Asset) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			for _, p := range a.Ports {
				for _, c := range checks {
					if ctx.Err() != nil || !c.match(p) {
						continue
					}
					res := c.run(ctx, net.JoinHostPort(a.IP, strconv.Itoa(p.Port)), opts)
					for i := range res {
						res[i].IP, res[i].Port = a.IP, p.Port
					}
					mu.Lock()
					results = append(results, res...)
					mu.Unlock()
				}
			}
		}(a)
	}
	wg.Wait()
	return results
}

func notVulnerable(id string) model.CheckResult { return model.CheckResult{CheckID: id} }

func found(id, title string, sev model.Severity, detail string) model.CheckResult {
	return model.CheckResult{CheckID: id, Vulnerable: true, Title: title, Severity: sev, Detail: detail}
}

// maskPassword 只保留首字符和长度，避免把可用的口令存进数据库。
func maskPassword(p string) string {
	if p == "" {
		return "（空）"
	}
	return p[:1] + strings.Repeat("*", len(p)-1)
}

func dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// --- Redis ---

func redisCommand(conn net.Conn, r *bufio.Reader, args ...string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return "", err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "$") { // bulk string：再读内容
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}
	return line, nil
}

func checkRedis(ctx context.Context, addr string, opts Options) []model.CheckResult {
	conn, err := dial(ctx, addr, opts.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	resp, err := redisCommand(conn, r, "INFO", "server")
	if err != nil {
		return nil
	}
	if !strings.HasPrefix(resp, "-") {
		version := ""
		for _, l := range strings.Split(resp, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "redis_version:"); ok {
				version = " " + v
			}
		}
		return []model.CheckResult{found("redis-unauth", "Redis 未授权访问", model.SeverityHigh,
			"无需密码即可执行命令（Redis"+version+"），可被用于写入 SSH 公钥 / 计划任务获取主机权限")}
	}
	results := []model.CheckResult{notVulnerable("redis-unauth")}
	if !opts.WeakPassword || !strings.Contains(resp, "NOAUTH") {
		return results
	}
	for i, pw := range RedisPasswords {
		if i > 0 {
			time.Sleep(opts.AttemptDelay)
		}
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		resp, err := redisCommand(conn, r, "AUTH", pw)
		if err != nil {
			return results
		}
		if resp == "+OK" {
			return append(results, found("redis-weak-password", "Redis 弱口令", model.SeverityHigh,
				"密码为常见弱口令 "+maskPassword(pw)))
		}
	}
	return append(results, notVulnerable("redis-weak-password"))
}

// --- Memcached ---

func checkMemcached(ctx context.Context, addr string, opts Options) []model.CheckResult {
	conn, err := dial(ctx, addr, opts.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		return nil
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(line, "STAT ") {
		return []model.CheckResult{found("memcached-unauth", "Memcached 未授权访问", model.SeverityMedium,
			"无需认证即可读写缓存数据；暴露在外时还可被用于 UDP 反射放大攻击")}
	}
	return []model.CheckResult{notVulnerable("memcached-unauth")}
}

// --- HTTP API（Elasticsearch / Docker）---

func httpGetJSON(ctx context.Context, url string, timeout time.Duration, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func checkElasticsearch(ctx context.Context, addr string, opts Options) []model.CheckResult {
	var info struct {
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	code, err := httpGetJSON(ctx, "http://"+addr+"/", opts.Timeout, &info)
	if err != nil && code == 0 {
		return nil // 连接失败或不是 HTTP：无法判断
	}
	if code == http.StatusOK && info.ClusterName != "" {
		return []model.CheckResult{found("elasticsearch-unauth", "Elasticsearch 未授权访问", model.SeverityHigh,
			fmt.Sprintf("集群 %s（版本 %s）无需认证即可读写索引数据", info.ClusterName, info.Version.Number))}
	}
	return []model.CheckResult{notVulnerable("elasticsearch-unauth")}
}

func checkDockerAPI(ctx context.Context, addr string, opts Options) []model.CheckResult {
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	code, err := httpGetJSON(ctx, "http://"+addr+"/version", opts.Timeout, &v)
	if err != nil && code == 0 {
		return nil
	}
	if code == http.StatusOK && v.APIVersion != "" {
		return []model.CheckResult{found("docker-api-unauth", "Docker Remote API 未授权访问", model.SeverityHigh,
			"Docker "+v.Version+" 的 API 无认证暴露，可直接创建特权容器获取宿主机 root 权限")}
	}
	return []model.CheckResult{notVulnerable("docker-api-unauth")}
}

// --- FTP ---

// ftpLogin 返回登录是否成功；连接或协议异常时 ok=false 且 err 非空。
func ftpLogin(ctx context.Context, addr, user, pass string, timeout time.Duration) (bool, error) {
	conn, err := dial(ctx, addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	readCode := func() (string, error) {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return "", err
			}
			// 多行响应以 "xyz-" 开头，最后一行为 "xyz "
			if len(line) >= 4 && line[3] == ' ' {
				return line[:3], nil
			}
		}
	}
	if code, err := readCode(); err != nil || code != "220" {
		return false, fmt.Errorf("unexpected greeting %q: %v", code, err)
	}
	fmt.Fprintf(conn, "USER %s\r\n", user)
	code, err := readCode()
	if err != nil {
		return false, err
	}
	if code == "230" {
		return true, nil
	}
	if code != "331" {
		return false, nil
	}
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	code, err = readCode()
	if err != nil {
		return false, err
	}
	_, _ = conn.Write([]byte("QUIT\r\n"))
	return code == "230", nil
}

func checkFTP(ctx context.Context, addr string, opts Options) []model.CheckResult {
	ok, err := ftpLogin(ctx, addr, "anonymous", "safe-scan@example.com", opts.Timeout)
	if err != nil {
		return nil
	}
	var results []model.CheckResult
	if ok {
		results = append(results, found("ftp-anonymous", "FTP 允许匿名登录", model.SeverityMedium,
			"anonymous 用户可登录，可能泄露或被上传文件"))
	} else {
		results = append(results, notVulnerable("ftp-anonymous"))
	}
	if !opts.WeakPassword {
		return results
	}
	for i, c := range FTPCredentials {
		if i > 0 {
			time.Sleep(opts.AttemptDelay)
		}
		ok, err := ftpLogin(ctx, addr, c.User, c.Pass, opts.Timeout)
		if err != nil {
			return results // 服务异常或开始拒绝连接：停止尝试，不下结论
		}
		if ok {
			return append(results, found("ftp-weak-password", "FTP 弱口令", model.SeverityHigh,
				"用户 "+c.User+" 使用常见弱口令 "+maskPassword(c.Pass)))
		}
	}
	return append(results, notVulnerable("ftp-weak-password"))
}

// --- SSH ---

func checkSSH(ctx context.Context, addr string, opts Options) []model.CheckResult {
	if !opts.WeakPassword {
		return nil
	}
	for i, c := range SSHCredentials {
		if i > 0 {
			time.Sleep(opts.AttemptDelay)
		}
		if ctx.Err() != nil {
			return nil
		}
		ok, err := sshLogin(addr, c, opts.Timeout)
		if err != nil {
			return nil // 网络错误或服务端限制：停止尝试，不下结论
		}
		if ok {
			return []model.CheckResult{found("ssh-weak-password", "SSH 弱口令", model.SeverityHigh,
				"用户 "+c.User+" 使用常见弱口令 "+maskPassword(c.Pass))}
		}
	}
	return []model.CheckResult{notVulnerable("ssh-weak-password")}
}

// sshLogin 尝试密码登录。认证失败返回 (false, nil)，网络 / 协议错误返回 err。
func sshLogin(addr string, c Credential, timeout time.Duration) (bool, error) {
	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            []ssh.AuthMethod{ssh.Password(c.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 只做口令检测，不建立可信会话
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		client.Close()
		return true, nil
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return false, nil
	}
	return false, err
}
