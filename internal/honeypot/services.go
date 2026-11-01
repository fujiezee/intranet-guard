package honeypot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"safe/internal/model"
)

// --- SSH：记录每次密码尝试，一律拒绝 ---

var (
	sshOnce   sync.Once
	sshSigner ssh.Signer
)

func serveSSH(s *session) {
	sshOnce.Do(func() {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		sshSigner, _ = ssh.NewSignerFromKey(key)
	})
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		MaxAuthTries:  6,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.report(model.HoneypotEvent{Username: c.User(), Password: string(pass),
				Detail: "SSH 密码登录尝试，客户端 " + printable(c.ClientVersion(), 60)})
			return nil, fmt.Errorf("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.report(model.HoneypotEvent{Username: c.User(), Detail: "SSH 公钥登录尝试 " + key.Type()})
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(sshSigner)
	reported := false
	cfg.BannerCallback = func(c ssh.ConnMetadata) string {
		if !reported {
			reported = true
			s.report(model.HoneypotEvent{Username: c.User(), Detail: "SSH 连接，客户端 " + printable(c.ClientVersion(), 60)})
		}
		return ""
	}
	_, _, _, err := ssh.NewServerConn(bufConn{s.conn, s.r}, cfg)
	if err != nil && !reported {
		// 只建立了 TCP 连接或握手未完成（端口扫描、版本探测）
		s.report(model.HoneypotEvent{Detail: "SSH 连接（未完成握手）"})
	}
}

// --- FTP ---

func serveFTP(s *session) {
	fmt.Fprint(s.conn, "220 (vsFTPd 3.0.5)\r\n")
	user := ""
	any := false
	for i := 0; i < 10; i++ {
		line, err := s.r.ReadString('\n')
		if err != nil {
			break
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			user = arg
			fmt.Fprint(s.conn, "331 Please specify the password.\r\n")
		case "PASS":
			any = true
			s.report(model.HoneypotEvent{Username: user, Password: arg, Detail: "FTP 登录尝试"})
			fmt.Fprint(s.conn, "530 Login incorrect.\r\n")
		case "QUIT":
			fmt.Fprint(s.conn, "221 Goodbye.\r\n")
			i = 10
		default:
			fmt.Fprint(s.conn, "530 Please login with USER and PASS.\r\n")
		}
	}
	if !any {
		s.report(model.HoneypotEvent{Username: user, Detail: "FTP 连接"})
	}
}

// --- Telnet ---

func readTelnetLine(s *session) (string, error) {
	var buf []byte
	for len(buf) < 256 {
		c, err := s.r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == 0xff { // IAC 协商序列：跳过后两个字节
			s.r.ReadByte()
			s.r.ReadByte()
			continue
		}
		if c == '\n' || c == '\r' {
			if len(buf) == 0 {
				continue
			}
			break
		}
		buf = append(buf, c)
	}
	return printable(buf, 128), nil
}

func serveTelnet(s *session) {
	fmt.Fprint(s.conn, "\r\nUbuntu 22.04.4 LTS\r\nlogin: ")
	user, err := readTelnetLine(s)
	if err != nil {
		s.report(model.HoneypotEvent{Detail: "Telnet 连接"})
		return
	}
	fmt.Fprint(s.conn, "Password: ")
	pass, _ := readTelnetLine(s)
	s.report(model.HoneypotEvent{Username: user, Password: pass, Detail: "Telnet 登录尝试"})
	fmt.Fprint(s.conn, "\r\nLogin incorrect\r\n")
}

// --- MySQL：发送握手包，从客户端回应中取出用户名，返回拒绝访问 ---

func mysqlPacket(seq byte, payload []byte) []byte {
	h := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	return append(h, payload...)
}

func serveMySQL(s *session) {
	salt := make([]byte, 20)
	rand.Read(salt)
	for i := range salt {
		salt[i] = salt[i]%94 + 33 // 可打印字符，与真实服务器一致
	}
	var p bytes.Buffer
	p.WriteByte(10)
	p.WriteString("5.7.44-log\x00")
	binary.Write(&p, binary.LittleEndian, uint32(4711))
	p.Write(salt[:8])
	p.WriteByte(0)
	caps := uint32(0x000fa7ff) // 不含 CLIENT_SSL：客户端会直接发送明文用户名
	binary.Write(&p, binary.LittleEndian, uint16(caps))
	p.WriteByte(0x21)
	binary.Write(&p, binary.LittleEndian, uint16(2))
	binary.Write(&p, binary.LittleEndian, uint16(caps>>16))
	p.WriteByte(21)
	p.Write(make([]byte, 10))
	p.Write(salt[8:])
	p.WriteByte(0)
	p.WriteString("mysql_native_password\x00")
	s.conn.Write(mysqlPacket(0, p.Bytes()))

	head := make([]byte, 4)
	if _, err := io.ReadFull(s.r, head); err != nil {
		s.report(model.HoneypotEvent{Detail: "MySQL 连接"})
		return
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	if n > 4096 {
		n = 4096
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(s.r, body); err != nil || len(body) < 33 {
		s.report(model.HoneypotEvent{Detail: "MySQL 连接"})
		return
	}
	user := body[32:]
	if i := bytes.IndexByte(user, 0); i >= 0 {
		user = user[:i]
	}
	username := printable(user, 64)
	s.report(model.HoneypotEvent{Username: username, Detail: "MySQL 登录尝试"})
	var e bytes.Buffer
	e.WriteByte(0xff)
	binary.Write(&e, binary.LittleEndian, uint16(1045))
	e.WriteString("#28000")
	fmt.Fprintf(&e, "Access denied for user '%s'@'%s' (using password: YES)", username, s.src.Addr().Unmap())
	s.conn.Write(mysqlPacket(head[3]+1, e.Bytes()))
}

// --- Redis：记录 AUTH 和攻击者执行的命令（常见如 CONFIG SET dir 写计划任务 / 公钥） ---

func readRESP(s *session) ([]string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil // 内联命令（如 telnet 手工输入）
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 || n > 64 {
		return nil, fmt.Errorf("bad RESP")
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := s.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(hdr, "$")))
		if err != nil || size < 0 || size > 64<<10 {
			return nil, fmt.Errorf("bad RESP")
		}
		b := make([]byte, size+2)
		if _, err := io.ReadFull(s.r, b); err != nil {
			return nil, err
		}
		args = append(args, string(b[:size]))
	}
	return args, nil
}

func serveRedis(s *session) {
	var cmds []string
	defer func() {
		if len(cmds) > 0 {
			s.report(model.HoneypotEvent{Detail: "Redis 命令：" + printable([]byte(strings.Join(cmds, "; ")), 300)})
		}
	}()
	for i := 0; i < 20; i++ {
		args, err := readRESP(s)
		if err != nil || len(args) == 0 {
			if i == 0 && len(cmds) == 0 {
				s.report(model.HoneypotEvent{Detail: "Redis 连接"})
			}
			return
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			user, pass := "default", args[len(args)-1]
			if len(args) == 3 {
				user = args[1]
			}
			s.report(model.HoneypotEvent{Username: user, Password: pass, Detail: "Redis AUTH 尝试"})
			fmt.Fprint(s.conn, "-WRONGPASS invalid username-password pair or user is disabled.\r\n")
		case "QUIT":
			fmt.Fprint(s.conn, "+OK\r\n")
			return
		default:
			cmds = append(cmds, strings.Join(args, " "))
			fmt.Fprint(s.conn, "-NOAUTH Authentication required.\r\n")
		}
	}
}

// --- HTTP：伪装成设备管理后台登录页 ---

const loginPage = `<!doctype html><html><head><meta charset="utf-8"><title>管理后台登录</title></head>
<body style="font-family:sans-serif;display:flex;justify-content:center;margin-top:120px">
<form method="post" action="/login" style="width:280px">
<h3>运维管理平台</h3>
<p><input name="username" placeholder="用户名" style="width:100%"></p>
<p><input name="password" type="password" placeholder="密码" style="width:100%"></p>
<p><button style="width:100%">登 录</button></p>{{MSG}}
</form></body></html>`

func serveHTTP(s *session) {
	for i := 0; i < 10; i++ {
		req, err := http.ReadRequest(s.r)
		if err != nil {
			if i == 0 {
				s.report(model.HoneypotEvent{Detail: "HTTP 连接"})
			}
			return
		}
		detail := fmt.Sprintf("HTTP %s %s UA=%s", req.Method, printable([]byte(req.URL.RequestURI()), 200),
			printable([]byte(req.UserAgent()), 120))
		msg := ""
		if req.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(req.Body, 8<<10))
			form, _ := url.ParseQuery(string(body))
			user, pass := form.Get("username"), form.Get("password")
			if user == "" {
				user = form.Get("user")
			}
			s.report(model.HoneypotEvent{Username: printable([]byte(user), 64), Password: pass, Detail: detail})
			msg = `<p style="color:#c00">用户名或密码错误</p>`
		} else {
			s.report(model.HoneypotEvent{Detail: detail})
		}
		page := strings.Replace(loginPage, "{{MSG}}", msg, 1)
		status := "200 OK"
		if msg != "" {
			status = "401 Unauthorized"
		}
		fmt.Fprintf(s.conn, "HTTP/1.1 %s\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
			status, len(page), page)
		if req.Close {
			return
		}
	}
}

// --- 通用 TCP（RDP、SMB 等）：只记录连接和首包 ---

func serveTCP(s *session) {
	buf := make([]byte, 512)
	n, _ := s.r.Read(buf)
	detail := "TCP 连接"
	if n > 0 {
		detail = fmt.Sprintf("TCP 连接，收到 %d 字节：%s", n, guessProtocol(buf[:n]))
	}
	s.report(model.HoneypotEvent{Detail: detail})
}

func guessProtocol(b []byte) string {
	switch {
	case len(b) > 4 && b[0] == 0x03 && b[1] == 0x00: // TPKT
		return "RDP 连接请求"
	case bytes.Contains(b, []byte("\xffSMB")) || bytes.Contains(b, []byte("\xfeSMB")):
		return "SMB 协商"
	case bytes.HasPrefix(b, []byte("GET ")) || bytes.HasPrefix(b, []byte("POST ")):
		return "HTTP 请求 " + printable(b, 80)
	}
	return printable(b, 60)
}
