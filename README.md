# safe — 内网防护系统

架构、告警规则与权限模型见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，迭代规划见 [docs/ROADMAP.md](docs/ROADMAP.md)。
当前完成：阶段 1 资产发现，阶段 2 Web 控制台 / 用户权限 / 资产变化告警，阶段 3 主机 Agent 审计，阶段 4 流量入侵检测（Suricata），阶段 5 漏洞与弱口令检测，阶段 6 节点证书认证（mTLS）/ PostgreSQL / ClickHouse，阶段 7 告警推送与操作审计。

## 一键安装（试运行 / 生产）

```bash
make release VERSION=0.1.0                       # 开发机：生成 dist/safe-0.1.0-linux-{amd64,arm64}.tar.gz
# 拷到管理中心服务器：
tar -xzf safe-0.1.0-linux-amd64.tar.gz && cd safe-0.1.0-linux-amd64 && sudo ./install.sh
```

安装完成会打印控制台地址和 admin 密码。探针 / Agent 在控制台"节点管理 → 生成注册令牌"后，
复制页面给出的一行命令到目标机器执行即可（Linux 用 root 执行；Windows 以管理员身份在 Windows PowerShell 5.1 中执行）。完整步骤、检查清单和常见问题见 [docs/PILOT.md](docs/PILOT.md)。

安装脚本的模拟测试（无需 root / systemd）：`scripts/test-install.sh`。

## 高可用部署（多个管理中心实例）

1. 准备 PostgreSQL 和 ClickHouse（各自按官方文档做主备 / 集群），所有实例使用同一组连接串（`-db`、`-events-db`）。
2. 在第一台机器上安装并启动一次，把生成的 `pki` 目录（CA 与服务端私钥）复制到其他实例。
3. 各实例启动参数加 `-node-urls https://实例1:8443,https://实例2:8443`：之后控制台生成的安装命令会把全部实例写入节点，
   节点连接失败时自动切换；推送、超时等后台任务自动选一个实例执行，该实例宕机后 5 秒内由其他实例接手。
4. 控制台可放在任意 HTTP 负载均衡后面（登录会话保存在数据库中，各实例通用）。

原理与压测结果见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 第 20 节；压测工具：`go run ./cmd/loadtest -h`。

## 开发环境运行

```bash
# 1. 构建前端（产物在 web/dist，由管理中心直接托管）
cd web && npm install && npm run build && cd ..

# 2. 启动管理中心：控制台 :8080，节点接入 :8443（mTLS）；首次启动在 pki/ 下生成内部 CA，请备份
export SAFE_INIT_ADMIN_PASSWORD=<初始管理员密码，至少 10 位>   # 可选，不设置则随机生成并打印在日志里
go run ./cmd/server -addr :8080 -node-addr :8443 -db safe.db -web web/dist -pki-dir pki
#   节点通过其他域名 / IP 访问管理中心时，用 -node-hosts 列出（默认为本机主机名和所有 IP）

# 3. 控制台"节点管理"生成注册令牌，在每个网段的探针机器上首次启动时带上令牌
SAFE_ENROLL_TOKEN=<令牌> go run ./cmd/probe -server https://<管理中心>:8443 -id seg-a
#   注册成功后证书保存在 -state 所在目录（默认 /var/lib/safe-probe），之后启动不再需要令牌
```

## 控制台 HTTPS

控制台默认是 HTTP，登录密码和会话令牌会明文传输（启动时有警告），生产环境请任选一种：

| 方式 | 启动参数 | 说明 |
| --- | --- | --- |
| 公司证书 | `-tls-cert safe.crt -tls-key safe.key` | 推荐 |
| 内部 CA 签发 | `-tls-internal` | 证书覆盖 `-node-hosts` 中的地址；管理员电脑需信任 `pki/ca.crt`（macOS：`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain pki/ca.crt`） |
| Nginx 反向代理 | `-addr 127.0.0.1:8080 -trusted-proxies 127.0.0.1/32` | 配置见 [deploy/nginx-safe.conf](deploy/nginx-safe.conf) |

使用反向代理时必须设置 `-trusted-proxies`，否则所有请求都显示为代理的 IP：审计记录不到真实来源，
一个人登录失败 5 次会把所有人锁住。只有来自这些地址的请求才会采信 `X-Forwarded-For`。

## 部署管理中心

[deploy/safe-server.service](deploy/safe-server.service) 是 systemd 单元（以非 root 的 `safe` 用户运行），安装步骤在文件头部。
数据库连接串放在 `/etc/safe/safe.env` 的 `SAFE_DB` / `SAFE_EVENTS_DB` 中，不要写在命令行上（会出现在进程列表里）。

## 备份与恢复

```bash
scripts/backup.sh                         # 主库 + pki/ + data/safe.env + ClickHouse 用户配置，保留最近 14 份
BACKUP_EVENTS=1 scripts/backup.sh         # 同时导出 ClickHouse 事件
SAFE_HOME=/var/lib/safe scripts/backup.sh /backup/safe     # systemd 部署
```

备份里有 CA 私钥和数据库密码，文件权限 0600，请放到受控位置；建议用 cron 每天执行。恢复：

1. 停止管理中心，解压备份：`tar -xzf safe-<时间>.tar.gz`
2. 放回 `pki/`、`data/`，以及主库：SQLite 直接替换 `safe.db`；PostgreSQL 用 `pg_restore --clean -d <库> safe.pgdump`
3. 有事件备份时导入 ClickHouse：
   `curl -H "X-ClickHouse-User: …" -H "X-ClickHouse-Key: …" "http://<主机>:8123/?query=INSERT+INTO+safe.host_events+FORMAT+Native" --data-binary @events/host_events.native`（ids_events 同理）
4. 启动管理中心。CA 不变，已注册的探针和 Agent 无需重新注册。

## 使用 PostgreSQL（生产环境推荐）

```bash
createdb safe
go run ./cmd/server -db 'postgres://safe:<密码>@<主机>:5432/safe?sslmode=require' ...
```

已经在用 SQLite 的，先停掉管理中心，把数据迁移过去再用 PostgreSQL 启动（目标库必须为空，失败不会留下半份数据）：

```bash
safe-server -migrate-from safe.db -db 'postgres://safe:<密码>@<主机>:5432/safe?sslmode=require'
```

迁移后原 `safe.db` 保持不动，可作为回退备份。多个管理中心实例可以共用同一个 PostgreSQL（需共享同一份 `pki/` 目录）。

## 使用 ClickHouse 存储事件（上千台主机时推荐）

```bash
export SAFE_EVENTS_DB='clickhouse://default:<密码>@<主机>:8123/safe'   # 用环境变量，密码不会出现在进程列表里
safe-server -db 'postgres://…' ...                                     # 也可以用 -events-db 参数
```

主机事件和 IDS 事件写入 ClickHouse（自动建库建表，90 天 TTL 自动过期），其余数据仍在主库。
从主库切换过来时，先停管理中心，把历史事件导入（目标已有事件时拒绝执行，主库中的事件保持不动）：

```bash
safe-server -db safe.db -import-events
```

单机部署可以用 `scripts/clickhouse-local.sh` 启动本机 ClickHouse：数据在 `data/clickhouse/`，只监听 127.0.0.1，
用户密码在 `data/clickhouse/users.xml`（SHA-256）。`data/` 下是运行时数据和密钥，已加入 `.gitignore`。

本机当前的启动方式：

```bash
scripts/clickhouse-local.sh &                     # 1. ClickHouse
source data/safe.env                              # 2. 读取 SAFE_EVENTS_DB 等配置（权限 0600）
./bin/safe-server -db safe.db -web web/dist -pki-dir pki
```

## 告警推送

管理员在控制台"推送与审计 → 告警推送"添加企业微信 / 钉钉 / 飞书群机器人或通用 Webhook，选择推送级别后点"测试"确认。
钉钉 / 飞书机器人如开启了"加签"请填写密钥；开启"自定义关键词"的，请把关键词设为"内网防护"。

> 从旧版共享 token 迁移：管理中心先保留 `SAFE_PROBE_TOKEN` / `SAFE_AGENT_TOKEN` 启动，
> 逐个节点用注册令牌改为证书方式（`-server https://...:8443`），全部迁移后删除这两个变量并重启管理中心。

## 部署主机 Agent

```bash
GOOS=linux GOARCH=amd64 go build -o bin/safe-agent-linux-amd64 ./cmd/agent
```

在控制台"节点管理"生成 Agent 注册令牌（批量部署可设置多次可用），
把二进制和 [deploy/safe-agent.service](deploy/safe-agent.service) 拷到目标服务器，按文件头部注释安装（需要 root）。
Agent 自动选择日志来源（auth.log / secure / journald），也可以用 `-auth-log`、`-fim-paths` 覆盖。
接入后在控制台"主机审计"页查看在线状态和审计日志。

## 漏洞检测

在"扫描任务"新建任务时选择**漏洞检测**：探针在端口扫描后检查未授权访问（Redis、Elasticsearch、Docker API、Memcached）、
FTP 匿名登录，管理中心同时按 Banner 匹配已知版本漏洞。结果在"漏洞"页，修复后再跑一次漏洞检测会自动标记为已修复。

**弱口令**（SSH / FTP / Redis）需要单独开启。它会产生真实的登录失败，可能触发账号锁定或其他安全设备告警，
开启前请与系统负责人确认，必要时在 IDS / 主机告警中为探针 IP 加抑制。

## 接入 Suricata（流量检测）

探针机器接交换机镜像口并安装 Suricata，按 [deploy/suricata-eve.yaml](deploy/suricata-eve.yaml) 配置只输出告警的 eve 文件，
然后启动探针时加上 `-eve /var/log/suricata/eve-alert.json`（systemd 单元见 [deploy/safe-probe.service](deploy/safe-probe.service)）。
告警在控制台"流量检测"页查看；确认的误报可以直接在事件上点"抑制"。

浏览器打开 `http://<管理中心>:8080`，用 `admin` 登录。首次登录后请修改密码。

建议流程：新网段先建一个**基线扫描**任务建立资产台账，之后的定期扫描只对变化（新主机、新端口、高危端口）告警。

前端开发：`cd web && npm run dev`（自动把 `/api` 代理到 `127.0.0.1:8080`）。

## API

除登录外，所有接口都需要 `Authorization: Bearer <token>`：

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -d '{"username":"admin","password":"..."}' | jq -r .token)

curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/tasks \
  -d '{"probe_id":"seg-a","targets":["10.1.0.0/24"],"baseline":true}'
curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/assets
curl -H "Authorization: Bearer $TOKEN" "localhost:8080/api/v1/alerts?status=open"
curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/alerts/1/ack
curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/stats
```

| 接口 | 权限 |
| --- | --- |
| `POST /auth/login`、`POST /auth/logout`、`GET /auth/me`、`POST /auth/password` | 登录用户 |
| `GET /stats`、`/assets`、`/assets/{ip}`、`/tasks`、`/tasks/{id}`、`/alerts` | viewer |
| `POST /tasks`、`POST /alerts/{id}/ack`、`/users` 增删查 | admin |
| `GET /vulns?status=&severity=&ip=` | viewer |
| `POST /vulns/{id}/status`（ignored / open） | admin |
| `GET /audit`、`/notify-channels` 增删查、`POST /notify-channels/{id}/test` | admin |
| `GET /agents`、`GET /host-events?agent_id=&type=&src_ip=` | viewer |
| `GET /ids/events?src_ip=&dest_ip=&signature_id=&max_severity=`、`GET /ids/suppressions` | viewer |
| `POST /ids/suppressions`、`DELETE /ids/suppressions/{id}` | admin |
| `GET /nodes`、`POST /nodes/{kind}/{id}/revoke`、`/enroll-tokens` 增删查 | admin |
| 节点端口 `GET /ca`、`POST /enroll` | 公开（注册令牌校验） |
| 节点端口 `/probe/*`、`/agent/report`、`/node/renew` | 节点客户端证书 |

## 测试

```bash
make test        # SQLite
make test-pg     # PostgreSQL：PG_DSN=postgres://user@host:5432/db?sslmode=disable make test-pg
make test-ch     # 事件存 ClickHouse：CH_URL=clickhouse://default:<密码>@127.0.0.1:8123 make test-ch（每个测试建独立库，结束后删除）
```

> 仅扫描你有权管理的网络。

## 许可证

[Apache License 2.0](LICENSE)

> 本项目用于防护你有权管理的网络。扫描、弱口令检测等功能请仅在获得授权的范围内使用。
