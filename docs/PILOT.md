# 试运行手册

目标：在一个网段、几台服务器上把整套系统跑起来，运行 1～2 周，收集真实环境中的问题。
全程只需要三类操作：管理中心执行一次 `install.sh`，在控制台点"生成注册令牌"，把给出的命令粘贴到目标机器。

## 0. 准备

| 角色 | 数量 | 要求 |
| --- | --- | --- |
| 管理中心 | 1 台 | Linux（x86_64 或 ARM64）、systemd、2 核 4G 起、root 权限 |
| 主机 Agent | 2～3 台 | 不同发行版各一台最好（如 Ubuntu、CentOS / Rocky、麒麟 / 统信）；systemd、sysvinit、OpenRC 均可 |
| 网络探针 | 1 台 | 放在要扫描的网段里；做流量检测还需要接交换机镜像口（SPAN） |

网络：Agent 和探针要能访问管理中心的 **8443** 端口；管理员电脑要能访问管理中心的 **443** 端口。

安装包：在开发机执行 `make release VERSION=0.1.0`，得到 `dist/safe-0.1.0-linux-amd64.tar.gz`（ARM 服务器用 arm64 包）。

## 1. 安装管理中心（约 1 分钟）

```bash
tar -xzf safe-0.1.0-linux-amd64.tar.gz && cd safe-0.1.0-linux-amd64
sudo ./install.sh
```

结束时会打印控制台地址、admin 密码（只显示一次）和 CA 指纹。浏览器提示证书不受信任是正常的（内部 CA），
核对指纹后继续访问，或把 `/var/lib/safe/pki/ca.crt` 导入管理员电脑的受信任根证书。登录后先改密码。

> 节点用其他域名 / IP 访问管理中心（如 NAT、域名）时，安装前设置 `SAFE_NODE_HOSTS=safe.corp,10.0.0.5`。
> 要用公司证书：`sudo SAFE_TLS_CERT=/path/cert.pem SAFE_TLS_KEY=/path/key.pem ./install.sh`。

## 2. 安装 Agent（每台约 10 秒）

控制台 → **节点管理** → **生成注册令牌**：类型选"主机 Agent"，可用次数填要装的台数。复制页面给出的命令，
在每台服务器上执行即可，形如：

```bash
curl -fsSLk --pinnedpubkey 'sha256//…' 'https://<管理中心>:8443/i/<令牌>' | sudo sh
```

几秒后在 **主机审计** 页能看到该主机在线。

- curl 低于 7.39 的系统（如 CentOS 7）用离线方式：在能联网的机器上下载 `install/agent.sh` 和安装包里的
  `downloads/safe-agent-linux-amd64`，拷过去执行
  `sudo SAFE_LOCAL_BIN=./safe-agent-linux-amd64 SAFE_ENROLL_TOKEN='…' sh agent.sh`。
- 升级：重新执行同一条命令（令牌过期也可以，已注册的节点不需要令牌）。卸载：命令末尾的 `sudo sh` 改成 `sudo SAFE_ACTION=uninstall sh`。

## 3. 安装探针（约 1 分钟）

**（可选）先装 Suricata 做流量检测**，探针安装时会自动发现：

```bash
# Ubuntu / Debian
sudo apt install -y suricata && sudo suricata-update && sudo systemctl restart suricata
# Rocky / CentOS Stream / RHEL（需 EPEL）
sudo dnf install -y epel-release && sudo dnf install -y suricata && sudo suricata-update && sudo systemctl restart suricata
```

把 `/etc/suricata/suricata.yaml` 中 `af-packet` 的 `interface` 改成接镜像口的网卡（Debian 系也可改 `/etc/default/suricata`），
确认 `/var/log/suricata/eve.json` 有内容。

然后在控制台生成"网络探针"类型的令牌，填写网段名（例如 `office-3f`），复制命令到探针机器执行。
网段名写在命令的地址里（`/i/<令牌>?id=office-3f`），命令同样以 `| sudo sh` 结尾。

## 4. 开始使用

1. **扫描任务** → 新建任务，探针选刚装的网段，目标填本网段（如 `10.1.3.0/24`），**勾选"基线扫描"**——
   第一次扫描只建立资产台账，不会产生几百条"新主机"告警。
2. 基线完成后再建一个**漏洞检测**任务（先不开弱口令）。
3. **推送与审计** → 添加企业微信 / 钉钉 / 飞书机器人，点"测试"确认能收到。
4. 之后每天或每周跑一次资产发现，新上线的主机和端口会告警。

## 5. 上线检查清单

- [ ] 控制台能登录，admin 密码已修改，另建了只读账号给查看的人
- [ ] 所有 Agent 在"主机审计"页显示在线
- [ ] 在一台 Agent 机器上故意输错 SSH 密码 10 次，5 分钟内出现"SSH 爆破"告警，并推送到群里
- [ ] 在一台 Agent 机器上 `sudo touch /etc/cron.d/safe-test`，30 秒内出现"文件篡改"告警（之后删除该文件）
- [ ] 基线扫描完成，资产数量和预期大致相符
- [ ] 漏洞检测完成，结果逐条确认是否属实
- [ ] （有 Suricata 时）"流量检测"页有事件
- [ ] 停掉一台 Agent（`systemctl stop safe-agent`），3 分钟内出现"Agent 离线"告警
- [ ] `/var/backups/safe` 第二天出现备份文件
- [ ] `/var/lib/safe/pki` 已另外拷贝一份到安全的地方

## 6. 试运行期间请记录

| 记录什么 | 怎么获取 |
| --- | --- |
| 安装失败或报错 | 屏幕输出 + `journalctl -u safe-agent -n 100`（或 safe-probe / safe-server） |
| 误报：不应该告警但告警了 | 控制台截图或告警内容，说明为什么是误报 |
| 漏报：应该告警但没有 | 当时做了什么操作、在哪台机器、几点 |
| 扫描耗时和网段大小 | "扫描任务"页的创建 / 完成时间 |
| 每天告警数量（按类型） | "告警"页 |
| 发行版和版本 | `cat /etc/os-release` |
| 卡顿、页面慢、占用高 | `top` 中 safe-* 进程的 CPU / 内存 |

试运行结束后把这些反馈回来，据此决定下一步的修复和功能优先级。

## 7. 常见问题

| 现象 | 处理 |
| --- | --- |
| 安装命令报 `curl: (90)` | 公钥指纹不匹配：访问到的不是这台管理中心（检查地址、是否有代理 / 中间设备） |
| 安装命令报 `curl: (7)` 或超时 | 到管理中心 8443 不通：检查防火墙、安全组 |
| `注册失败` + `token is invalid, expired or used up` | 令牌过期或次数用完，重新生成 |
| `注册失败` + `already enrolled` | 该节点 ID 已注册过：控制台吊销后重装，或换 `SAFE_AGENT_ID` |
| 注册后连不上、日志有 `certificate is valid for …, not …` | 节点用的地址不在管理中心证书里：在 `/etc/safe/safe.env` 加一行 `SAFE_NODE_HOSTS='域名,IP'`，再执行一次 `sudo ./install.sh`（升级模式，会按配置重新生成服务并重启） |
| Agent 没有登录事件 | 发行版日志位置不同：`journalctl -u safe-agent` 中查看 auth 日志报错，反馈发行版信息 |
| 管理中心启动失败 | `journalctl -u safe-server -n 50`；常见是 443 / 8443 端口被占用，可用 `SAFE_CONSOLE_PORT` 换端口 |
| 完全卸载 | 节点：`SAFE_ACTION=uninstall`；管理中心：`sudo /path/to/install.sh uninstall`（加 `--purge` 删除数据） |
