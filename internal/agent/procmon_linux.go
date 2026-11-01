package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// 进程监控使用内核的进程连接器（netlink proc connector，2.6.15 起支持，CentOS 7 也可用）：
// 每次 exec 由内核推送 PID，再从 /proc 读取命令行等信息。不依赖 eBPF 和编译工具链；
// 代价是极短命的进程可能在读取前已退出，读不到命令行（检测上可接受，见 ARCHITECTURE.md）。
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
	nlmsgHdrLen       = 16
	cnMsgLen          = 20
)

// startProcMonitor 开始监听 exec 事件，每次执行调用 handle。需要 root（CAP_NET_ADMIN）。
func startProcMonitor(ctx context.Context, handle func(ExecInfo)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink bind: %w", err)
	}
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:], uint32(len(msg)))
	ne.PutUint16(msg[4:], unix.NLMSG_DONE)
	ne.PutUint32(msg[12:], uint32(os.Getpid()))
	ne.PutUint32(msg[16:], cnIdxProc)
	ne.PutUint32(msg[20:], cnValProc)
	ne.PutUint16(msg[32:], 4)
	ne.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("subscribe proc events: %w", err)
	}

	go func() {
		<-ctx.Done()
		unix.Close(fd)
	}()
	go func() {
		buf := make([]byte, 64<<10)
		users := &userCache{m: map[string]string{}}
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if err == unix.ENOBUFS {
					continue // 事件过多被内核丢弃，继续接收
				}
				return
			}
			for off := 0; off+nlmsgHdrLen <= n; {
				l := int(ne.Uint32(buf[off:]))
				if l < nlmsgHdrLen || off+l > n {
					break
				}
				p := buf[off+nlmsgHdrLen : off+l]
				if len(p) >= cnMsgLen+24 && ne.Uint32(p[cnMsgLen:]) == procEventExec {
					tgid := int(ne.Uint32(p[cnMsgLen+20:]))
					if e, ok := readExecInfo(tgid, users); ok {
						handle(e)
					}
				}
				off += (l + 3) &^ 3
			}
		}
	}()
	return nil
}

func readExecInfo(pid int, users *userCache) (ExecInfo, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	e := ExecInfo{PID: pid}
	cmd, err := os.ReadFile(dir + "/cmdline")
	if err != nil {
		return e, false // 进程已退出
	}
	if len(cmd) > 2048 {
		cmd = cmd[:2048]
	}
	e.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
	e.Exe, _ = os.Readlink(dir + "/exe")
	e.Comm = readTrim(dir + "/comm")
	if st, err := os.ReadFile(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if v, ok := strings.CutPrefix(line, "PPid:"); ok {
				e.PPID, _ = strconv.Atoi(strings.TrimSpace(v))
			} else if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					e.User = users.name(f[0])
				}
			}
		}
	}
	if st, err := os.ReadFile(dir + "/stat"); err == nil {
		if i := strings.LastIndexByte(string(st), ')'); i > 0 {
			if f := strings.Fields(string(st[i+1:])); len(f) > 4 {
				e.TTY = f[4] != "0" // tty_nr
			}
		}
	}
	// 与 Agent 同一 cgroup 的进程是 Agent 自己启动的（自检、处置命令）：以 DaemonSet 运行时 Agent 本身在 Pod 中，
	// 这些进程不应被当作业务容器内的进程
	if cg, err := os.ReadFile(dir + "/cgroup"); err == nil && string(cg) != selfCgroup {
		e.Container = pods.resolve(ParseCgroup(string(cg)))
	}
	if e.PPID > 0 {
		pdir := "/proc/" + strconv.Itoa(e.PPID)
		e.ParentComm = readTrim(pdir + "/comm")
		e.ParentExe, _ = os.Readlink(pdir + "/exe")
	}
	// 只对 shell 检查标准输入输出（开销较大）：连接到 TCP 而不是管道 / 本地套接字即为反弹 shell
	if shells[e.Comm] || shells[filepath.Base(e.Exe)] {
		for _, fd := range []string{"0", "1"} {
			if remote, ok := tcpPeerOfFD(dir, fd); ok {
				e.StdioNetwork, e.StdioRemote = true, remote
				break
			}
		}
	}
	return e, true
}

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

// tcpPeerOfFD 判断进程的某个文件描述符是否为 TCP 连接，返回对端地址。
// 在进程自己的网络命名空间（/proc/<pid>/net）里按套接字 inode 查找。
func tcpPeerOfFD(dir, fd string) (string, bool) {
	link, err := os.Readlink(dir + "/fd/" + fd)
	if err != nil || !strings.HasPrefix(link, "socket:[") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
	for _, table := range []string{"/net/tcp", "/net/tcp6"} {
		f, err := os.Open(dir + table)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) > 9 && fields[9] == inode {
				f.Close()
				return parseProcNetAddr(fields[2]), true
			}
		}
		f.Close()
	}
	return "", false
}

// parseProcNetAddr 解析 /proc/net/tcp 中的地址：IPv4 为 "0100007F:1F90"（小端），IPv6 为 32 位十六进制。
func parseProcNetAddr(s string) string {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	port, _ := strconv.ParseUint(hexPort, 16, 16)
	b, err := hex.DecodeString(hexIP)
	if err != nil {
		return s
	}
	for i := 0; i+4 <= len(b); i += 4 { // 每 4 字节为主机字节序
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.JoinHostPort(net.IP(b).String(), strconv.Itoa(int(port)))
}

type userCache struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *userCache) name(uid string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n, ok := c.m[uid]; ok {
		return n
	}
	n := uid
	if u, err := user.LookupId(uid); err == nil {
		n = u.Username
	}
	c.m[uid] = n
	return n
}

// pods 用于把容器进程对应到 Kubernetes Pod（节点上的 /var/log/pods）。
var pods = newPodIndex("/var/log/pods")

var selfCgroup = func() string {
	b, _ := os.ReadFile("/proc/self/cgroup")
	return string(b)
}()
