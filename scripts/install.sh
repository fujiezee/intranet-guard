#!/bin/sh
# 管理中心一键安装 / 升级 / 卸载。在解压后的安装包目录中执行：
#
#   sudo ./install.sh                 安装；再次执行即升级（保留数据和配置）
#   sudo ./install.sh uninstall       卸载程序，保留数据（/var/lib/safe）和配置（/etc/safe）
#   sudo ./install.sh uninstall --purge   连同数据、配置、备份一起删除
#
# 可选环境变量（首次安装时写入 /etc/safe/safe.env，之后修改该文件后 systemctl restart safe-server）：
#   SAFE_CONSOLE_PORT   控制台 HTTPS 端口，默认 443
#   SAFE_NODE_PORT      探针 / Agent 接入端口，默认 8443
#   SAFE_NODE_HOSTS     节点访问管理中心用的域名 / IP（逗号分隔），默认本机主机名和所有 IP
#   SAFE_DB             主库，默认 SQLite（/var/lib/safe/safe.db）；可设为 postgres://…
#   SAFE_EVENTS_DB      ClickHouse 事件库 clickhouse://…，默认不用
#   SAFE_TLS_CERT / SAFE_TLS_KEY   控制台使用公司证书；不设则由内部 CA 签发
set -eu

# SAFE_TEST_ROOT 仅用于测试：把所有系统路径放到一个临时目录下
R=${SAFE_TEST_ROOT:-}
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=$R/opt/safe
STATE=$R/var/lib/safe
CONF=$R/etc/safe
ENV_FILE=$CONF/safe.env
UNIT=$R/etc/systemd/system/safe-server.service
CRON=$R/etc/cron.d/safe-backup
BACKUPS=$R/var/backups/safe

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m注意：\033[0m%s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请用 root 运行：sudo ./install.sh"
command -v systemctl >/dev/null 2>&1 || die "需要 systemd"
command -v curl >/dev/null 2>&1 || die "需要 curl"
command -v sqlite3 >/dev/null 2>&1 || warn "未安装 sqlite3，每日备份将无法备份 SQLite 数据库（apt/yum install sqlite3 或 sqlite）"

if [ "${1:-}" = uninstall ]; then
	say "卸载管理中心"
	systemctl disable --now safe-server 2>/dev/null || true
	rm -f "$UNIT" "$CRON"
	rm -rf "$PREFIX"
	systemctl daemon-reload
	if [ "${2:-}" = --purge ]; then
		rm -rf "$STATE" "$CONF" "$BACKUPS"
		say "已删除程序、数据、配置和备份"
	else
		say "已卸载程序。数据保留在 ${STATE}，配置在 ${CONF}，备份在 $BACKUPS"
	fi
	exit 0
fi

[ -x "$HERE/safe-server" ] || die "在安装包目录中运行（找不到 $HERE/safe-server）"
"$HERE/safe-server" -h >/dev/null 2>&1 || die "safe-server 无法在本机运行：安装包的架构（amd64 / arm64）与本机不符？"

UPGRADE=0
[ -f "$ENV_FILE" ] && UPGRADE=1

# --- 用户与目录 ---
if ! id safe >/dev/null 2>&1; then
	say "创建系统用户 safe"
	useradd --system --home-dir /var/lib/safe --shell "$(command -v nologin || echo /bin/false)" safe
fi
install -d -m 755 "$PREFIX"
install -d -m 700 -o safe -g safe "$STATE"
install -d -m 750 -o root -g safe "$CONF"
install -d -m 700 "$BACKUPS"

# --- 程序 ---
if [ "$UPGRADE" = 1 ] && [ -x "$PREFIX/backup.sh" ]; then
	# 升级前先备份一次（数据库、CA、配置），升级出问题时可以恢复
	say "升级前备份到 $BACKUPS"
	( set -a; . "$ENV_FILE"; set +a; SAFE_HOME=$STATE SAFE_CONF=$CONF "$PREFIX/backup.sh" "$BACKUPS" ) >/dev/null 2>&1 ||
		warn "升级前备份失败（继续升级）；可稍后手动执行 $PREFIX/backup.sh"
fi
say "安装程序到 $PREFIX"
systemctl stop safe-server 2>/dev/null || true
install -m 755 "$HERE/safe-server" "$PREFIX/safe-server"
install -m 755 "$HERE/backup.sh" "$PREFIX/backup.sh"
rm -rf "$PREFIX/web" "$PREFIX/downloads"
cp -R "$HERE/web" "$PREFIX/web"
cp -R "$HERE/downloads" "$PREFIX/downloads"
chmod -R a+rX "$PREFIX"

# --- 配置（只在首次安装时生成，升级不覆盖）---
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; } # 给 systemd / sh 都能读的单引号值
ADMIN_PASSWORD=
if [ "$UPGRADE" = 0 ]; then
	say "生成配置 $ENV_FILE"
	ADMIN_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-16)
	umask 027
	{
		echo "SAFE_INIT_ADMIN_PASSWORD=$(q "$ADMIN_PASSWORD")"
		echo "SAFE_DB=$(q "${SAFE_DB:-$STATE/safe.db}")"
		[ -n "${SAFE_EVENTS_DB:-}" ] && echo "SAFE_EVENTS_DB=$(q "$SAFE_EVENTS_DB")"
		echo "SAFE_CONSOLE_PORT=$(q "${SAFE_CONSOLE_PORT:-443}")"
		echo "SAFE_NODE_PORT=$(q "${SAFE_NODE_PORT:-8443}")"
		[ -n "${SAFE_NODE_HOSTS:-}" ] && echo "SAFE_NODE_HOSTS=$(q "$SAFE_NODE_HOSTS")"
		true
	} >"$ENV_FILE"
	if [ -n "${SAFE_TLS_CERT:-}" ]; then
		[ -f "$SAFE_TLS_CERT" ] && [ -f "${SAFE_TLS_KEY:-}" ] || die "SAFE_TLS_CERT / SAFE_TLS_KEY 文件不存在"
		install -m 640 -o root -g safe "$SAFE_TLS_CERT" "$CONF/tls.crt"
		install -m 640 -o root -g safe "$SAFE_TLS_KEY" "$CONF/tls.key"
	fi
	chown root:safe "$ENV_FILE"
	chmod 640 "$ENV_FILE"
	umask 022
fi

# 读取当前配置生成 systemd 单元
set -a
. "$ENV_FILE"
set +a
CONSOLE_PORT=${SAFE_CONSOLE_PORT:-443}
NODE_PORT=${SAFE_NODE_PORT:-8443}
TLS_ARGS="-tls-internal"
[ -f "$CONF/tls.crt" ] && TLS_ARGS="-tls-cert $CONF/tls.crt -tls-key $CONF/tls.key"
HOST_ARGS=
[ -n "${SAFE_NODE_HOSTS:-}" ] && HOST_ARGS="-node-hosts $SAFE_NODE_HOSTS"

say "注册 systemd 服务 safe-server"
install -d "$(dirname "$UNIT")"
cat >"$UNIT" <<EOF
[Unit]
Description=safe management server
After=network-online.target postgresql.service clickhouse-server.service
Wants=network-online.target

[Service]
User=safe
Group=safe
# 数据库连接串等从环境文件读取，不出现在进程列表中
EnvironmentFile=$ENV_FILE
WorkingDirectory=$STATE
ExecStart=$PREFIX/safe-server -addr :$CONSOLE_PORT -node-addr :$NODE_PORT $TLS_ARGS $HOST_ARGS -pki-dir $STATE/pki -web $PREFIX/web -dist-dir $PREFIX/downloads
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$STATE
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF

# --- 每日备份 ---
install -d "$(dirname "$CRON")"
cat >"$CRON" <<EOF
# 每天 02:30 备份管理中心（数据库、CA、配置），保留 14 份，见 $PREFIX/backup.sh
30 2 * * * root set -a; . $ENV_FILE; set +a; SAFE_HOME=$STATE SAFE_CONF=$CONF $PREFIX/backup.sh $BACKUPS >/dev/null 2>&1
EOF
chmod 644 "$CRON"

# --- 防火墙（只处理已启用的 firewalld / ufw）---
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
	say "firewalld 放行 $CONSOLE_PORT/tcp、$NODE_PORT/tcp"
	firewall-cmd --permanent --add-port="$CONSOLE_PORT/tcp" --add-port="$NODE_PORT/tcp" >/dev/null
	firewall-cmd --reload >/dev/null
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
	say "ufw 放行 $CONSOLE_PORT/tcp、$NODE_PORT/tcp"
	ufw allow "$CONSOLE_PORT/tcp" >/dev/null
	ufw allow "$NODE_PORT/tcp" >/dev/null
fi

# --- 启动 ---
say "启动 safe-server"
systemctl daemon-reload
systemctl enable safe-server >/dev/null 2>&1
systemctl restart safe-server
i=0
until curl -fsk -o /dev/null "https://127.0.0.1:$CONSOLE_PORT/" 2>/dev/null; do
	i=$((i + 1))
	if [ $i -ge 30 ]; then
		journalctl -u safe-server -n 30 --no-pager >&2 || true
		die "safe-server 启动失败，见上方日志（常见原因：端口 $CONSOLE_PORT / $NODE_PORT 被占用、数据库连不上）"
	fi
	sleep 1
done

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$IP" ] || IP=$(hostname)
URL="https://$IP"
[ "$CONSOLE_PORT" = 443 ] || URL="$URL:$CONSOLE_PORT"
FP=$(openssl x509 -in "$STATE/pki/ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)

echo
if [ "$UPGRADE" = 1 ]; then
	say "升级完成，数据和配置未改动"
	echo "    控制台：$URL"
else
	say "安装完成"
	echo
	echo "    控制台：  $URL"
	echo "    用户名：  admin"
	echo "    密码：    $ADMIN_PASSWORD      （只显示这一次，登录后请立即修改）"
	echo
	echo "    浏览器会提示证书不受信任：这是管理中心内部 CA 签发的证书。"
	echo "    可以确认指纹后继续访问，或把 $STATE/pki/ca.crt 导入管理员电脑的受信任根证书。"
	[ -n "$FP" ] && echo "    CA 指纹（SHA-256）：$FP"
	echo
	echo "    下一步：登录控制台 → 节点管理 → 生成注册令牌，把页面给出的一行命令复制到"
	echo "    要安装 Agent / 探针的服务器上执行（这些服务器需要能访问本机 $NODE_PORT 端口）。"
	warn "请备份 $STATE/pki（内部 CA），已配置每日自动备份到 $BACKUPS"
fi
