#!/bin/sh
# 一键安装脚本的模拟测试：不需要 root 和 systemd，可在开发机上运行。
#
# 用替身命令（systemctl / useradd / id / install 等）代替系统命令，所有系统路径放到临时目录（SAFE_TEST_ROOT），
# 但安装脚本本身、公钥指纹下载、节点注册、mTLS 通信都是真实执行的。覆盖：
#   管理中心安装 → 登录 → 生成令牌 → Agent / 探针一键安装并注册 → 错误指纹被拒 → 升级（数据和密码保留）→
#   /i/<令牌> 一行命令 + 没有 systemd 的系统（sysvinit 脚本、进程退出后自动重启）→ 卸载
# 不覆盖：真实 systemd / sysvinit / OpenRC、各 Linux 发行版差异、防火墙。
#
# 用法：scripts/test-install.sh        （需要 go、npm 已构建的 web/dist、curl、openssl、python3）
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
export SAFE_TEST_ROOT="$WORK/root"
# 开发机上没有 /run/systemd/system，节点安装脚本默认会按 sysvinit 处理；除专门测试 sysvinit 的部分外都用替身 systemctl
export SAFE_INIT=systemd
STUBS="$WORK/stubs"
BUNDLE="$WORK/bundle"
CONSOLE_PORT=19443
NODE_PORT=19444
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31m✗\033[0m %s\n' "$*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
	for p in "$WORK"/root*/run/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done
	[ "$FAIL" = 0 ] && rm -rf "$WORK" || echo "保留现场：$WORK"
}
trap cleanup EXIT

mkdir -p "$STUBS" "$BUNDLE/downloads" "$SAFE_TEST_ROOT/run"

echo "== 构建模拟安装包"
cd "$ROOT_DIR"
[ -f web/dist/index.html ] || { echo "先构建前端：cd web && npm run build"; exit 1; }
go build -o "$BUNDLE/safe-server" ./cmd/server
# 模拟环境中 uname -m 返回 arm64，本机程序以 linux-arm64 的名字提供下载
go build -o "$BUNDLE/downloads/safe-agent-linux-arm64" ./cmd/agent
go build -o "$BUNDLE/downloads/safe-probe-linux-arm64" ./cmd/probe
cp -R web/dist "$BUNDLE/web"
# 与 make release 相同的方式放入安装包
install -m 755 scripts/install.sh scripts/backup.sh "$BUNDLE/"

# --- 替身命令 ---
stub() { printf '#!/bin/sh\n%s\n' "$2" >"$STUBS/$1" && chmod +x "$STUBS/$1"; }
stub id 'if [ "${1:-}" = -u ]; then echo 0; fi; exit 0'
stub useradd 'exit 0'
stub chown 'exit 0'
stub uname 'if [ "${1:-}" = -m ]; then echo arm64; else exec /usr/bin/uname "$@"; fi'
stub hostname 'if [ "${1:-}" = -I ]; then echo 127.0.0.1; else exec /bin/hostname "$@"; fi'
stub journalctl 'tail -n 30 "$SAFE_TEST_ROOT"/run/*.log 2>/dev/null; exit 0'
# install：去掉 -o / -g（需要 root），其余交给系统 install
cat >"$STUBS/install" <<'EOF'
#!/bin/sh
args=""
while [ $# -gt 0 ]; do
	case "$1" in
	-o | -g) shift 2 ;;
	*) args="$args '$(printf '%s' "$1" | sed "s/'/'\\\\''/g")'"; shift ;;
	esac
done
eval "exec /usr/bin/install $args"
EOF
chmod +x "$STUBS/install"
# systemctl：按单元文件的 EnvironmentFile / ExecStart 在后台启动进程
cat >"$STUBS/systemctl" <<'EOF'
#!/bin/sh
RUN=$SAFE_TEST_ROOT/run
cmd=$1; shift
name=
for a in "$@"; do case "$a" in --*) ;; *) name=${a%.service} ;; esac; done
unit=$SAFE_TEST_ROOT/etc/systemd/system/$name.service
stop() {
	if [ -f "$RUN/$name.pid" ]; then kill "$(cat "$RUN/$name.pid")" 2>/dev/null || true; rm -f "$RUN/$name.pid"; sleep 1; fi
}
start() {
	[ -f "$unit" ] || exit 5
	stop
	envf=$(sed -n 's/^EnvironmentFile=//p' "$unit")
	execs=$(sed -n 's/^ExecStart=//p' "$unit")
	( if [ -n "$envf" ]; then set -a; . "$envf"; set +a; fi; exec sh -c "exec $execs" ) >>"$RUN/$name.log" 2>&1 &
	echo $! >"$RUN/$name.pid"
}
case "$cmd" in
daemon-reload) ;;
enable) case " $* " in *" --now "*) start ;; esac ;;
start | restart) start ;;
stop) stop ;;
disable) case " $* " in *" --now "*) stop ;; esac ;;
is-active) [ -f "$RUN/$name.pid" ] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null ;;
esac
EOF
chmod +x "$STUBS/systemctl"
export PATH="$STUBS:$PATH"

api() { # api METHOD PATH [JSON]
	curl -fsSk -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		"https://127.0.0.1:$CONSOLE_PORT/api/v1$2" ${3:+-d "$3"}
}
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
perm() { python3 -c 'import os,sys;print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1" 2>/dev/null; }

echo "== 安装管理中心"
check "安装脚本有执行权限（文档要求 sudo ./install.sh）" '[ -x "$BUNDLE/install.sh" ] && [ -x "$BUNDLE/backup.sh" ]'
OUT=$(SAFE_CONSOLE_PORT=$CONSOLE_PORT SAFE_NODE_PORT=$NODE_PORT "$BUNDLE/install.sh" 2>&1) || { echo "$OUT"; exit 1; }
ADMIN_PW=$(printf '%s\n' "$OUT" | sed -n 's/^ *密码： *\([A-Za-z0-9]*\).*/\1/p')
check "安装成功并打印管理员密码" '[ -n "$ADMIN_PW" ]'
check "配置文件权限 640" '[ "$(perm "$SAFE_TEST_ROOT/etc/safe/safe.env")" = 640 ]'
check "systemd 单元不含数据库连接串" '! grep -q "SAFE_DB\|postgres://" "$SAFE_TEST_ROOT/etc/systemd/system/safe-server.service" || grep -q "^EnvironmentFile" "$SAFE_TEST_ROOT/etc/systemd/system/safe-server.service" && ! grep -q "ExecStart=.*-db " "$SAFE_TEST_ROOT/etc/systemd/system/safe-server.service"'
check "每日备份已配置" 'grep -q backup.sh "$SAFE_TEST_ROOT/etc/cron.d/safe-backup"'
check "控制台是 HTTPS（内部 CA）" 'curl -fs --cacert "$SAFE_TEST_ROOT/var/lib/safe/pki/ca.crt" -o /dev/null "https://127.0.0.1:$CONSOLE_PORT/"'

TOKEN=$(curl -fsSk -X POST "https://127.0.0.1:$CONSOLE_PORT/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | json 'd["token"]')
check "用打印的密码登录" '[ -n "$TOKEN" ]'
PIN=$(api GET /install-info | json 'd["pin"]')
check "安装信息包含公钥指纹" 'printf %s "$PIN" | grep -q "^sha256//"'

echo "== Agent 一键安装"
AT=$(api POST /enroll-tokens '{"kind":"agent","max_uses":2,"ttl_hours":1}' | json 'd["token"]')
NODE_URL="https://127.0.0.1:$NODE_PORT"
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/agent.sh" | SAFE_ENROLL_TOKEN="$AT" SAFE_AGENT_ID=sim-web01 sh 2>&1) || true
printf '%s\n' "$OUT" | sed 's/^/    /'
check "Agent 安装并注册成功" 'printf "%s" "$OUT" | grep -q "已运行"'
check "注册后令牌已从配置中删除" '[ ! -s "$SAFE_TEST_ROOT/etc/safe-agent.env" ]'
check "Agent 私钥权限 600" '[ "$(perm "$SAFE_TEST_ROOT/var/lib/safe-agent/node.key")" = 600 ]'
sleep 3
check "控制台看到 Agent 在线" 'api GET /agents | json "[a[\"status\"] for a in d if a[\"id\"]==\"sim-web01\"]" | grep -q online'

echo "== Agent 离线安装（不下载，模拟 curl 过旧的系统）"
curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/agent.sh" -o "$WORK/agent.sh"
mkdir -p "$WORK/root2/run"
OUT=$(SAFE_TEST_ROOT="$WORK/root2" SAFE_LOCAL_BIN="$BUNDLE/downloads/safe-agent-linux-arm64" SAFE_ENROLL_TOKEN="$AT" \
	SAFE_AGENT_ID=sim-db01 PATH="$STUBS:/usr/bin:/bin:/usr/sbin:/sbin" sh "$WORK/agent.sh" 2>&1) || true
check "离线安装并注册成功" 'printf "%s" "$OUT" | grep -q "使用本地程序" && printf "%s" "$OUT" | grep -q "已运行"'

echo "== 错误的公钥指纹（模拟中间人）"
WRONG='sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
check "指纹不匹配时 curl 拒绝下载脚本" '! curl -fsSLk --pinnedpubkey "$WRONG" "$NODE_URL/install/agent.sh" -o /dev/null 2>/dev/null'

echo "== 探针一键安装"
PT=$(api POST /enroll-tokens '{"kind":"probe","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/probe.sh" | SAFE_ENROLL_TOKEN="$PT" sh 2>&1) || true
check "缺少 SAFE_PROBE_ID 时给出提示" 'printf "%s" "$OUT" | grep -q "SAFE_PROBE_ID"'
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/probe.sh" | SAFE_ENROLL_TOKEN="$PT" SAFE_PROBE_ID=sim-seg sh 2>&1) || true
check "探针安装并注册成功" 'printf "%s" "$OUT" | grep -q "已运行"'
TASK=$(api POST /tasks '{"probe_id":"sim-seg","targets":["127.0.0.1"],"ports":['"$CONSOLE_PORT"']}' | json 'd["id"]')
sleep 13
check "探针领取并完成扫描任务" 'api GET /tasks/$TASK | json "d[\"status\"]" | grep -q done'

echo "== 升级"
OUT=$(SAFE_CONSOLE_PORT=$CONSOLE_PORT SAFE_NODE_PORT=$NODE_PORT sh "$BUNDLE/install.sh" 2>&1) || { echo "$OUT"; exit 1; }
check "再次执行为升级" 'printf "%s" "$OUT" | grep -q "升级完成"'
check "升级后原密码仍可登录" 'curl -fsSk -X POST "https://127.0.0.1:$CONSOLE_PORT/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" -o /dev/null'
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/agent.sh" | sh 2>&1) || true
check "已注册的 Agent 无需令牌即可升级" 'printf "%s" "$OUT" | grep -q "已运行"'
sleep 3
TOKEN=$(curl -fsSk -X POST "https://127.0.0.1:$CONSOLE_PORT/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | json 'd["token"]')
check "升级后节点证书仍然有效（2 个 Agent + 1 个探针）" '[ "$(api GET /nodes | json "len([n for n in d if n[\"status\"]==\"active\"])")" = 3 ]'

echo "== /i/<令牌> 一行命令，没有 systemd 的系统（sysvinit）"
R3="$WORK/root3"
mkdir -p "$R3/run"
ST=$(api POST /enroll-tokens '{"kind":"probe","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/i/$ST?id=sim-sysv" | SAFE_TEST_ROOT="$R3" SAFE_INIT=sysv sh 2>&1) || true
printf '%s\n' "$OUT" | sed 's/^/    /'
check "命令中不带环境变量即可安装并注册" 'printf "%s" "$OUT" | grep -q "已运行（sysv"'
check "生成 /etc/init.d 脚本而不是 systemd 单元" '[ -x "$R3/etc/init.d/safe-probe" ] && [ ! -f "$R3/etc/systemd/system/safe-probe.service" ]'
check "注册后令牌已从配置中删除" '[ ! -s "$R3/etc/safe-probe.env" ]'
check "init.d status 显示运行中" '"$R3/etc/init.d/safe-probe" status >/dev/null'
pkill -f "^$R3/usr/local/bin/safe-probe" || true
sleep 7
check "进程退出后自动重启" 'pgrep -f "^$R3/usr/local/bin/safe-probe" >/dev/null'
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/i/$ST?id=sim-sysv" | SAFE_TEST_ROOT="$R3" SAFE_INIT=sysv sh 2>&1) || true
check "令牌用完后，同一条命令用于升级" 'printf "%s" "$OUT" | grep -q "已运行（sysv"'
RUNNER_PID=$(cat "$R3/run/safe-probe.pid")
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/i/$ST" | SAFE_TEST_ROOT="$R3" SAFE_INIT=sysv SAFE_ACTION=uninstall sh 2>&1) || true
sleep 1
check "卸载后服务停止、init.d 脚本删除" '[ ! -f "$R3/etc/init.d/safe-probe" ] && ! kill -0 "$RUNNER_PID" 2>/dev/null && ! pgrep -f "^$R3/usr/local/bin/safe-probe" >/dev/null'

mkdir -p "$WORK/root4/run"
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/i/$ST?id=sim-new" | SAFE_TEST_ROOT="$WORK/root4" SAFE_INIT=sysv sh 2>&1) || true
check "用完的令牌在新机器上提示重新生成" 'printf "%s" "$OUT" | grep -q "已过期或已用完"'
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/i/$(printf '0%.0s' $(seq 32)).$(printf 'a%.0s' $(seq 64))" | sh 2>&1) && bad "不存在的令牌应当失败" || ok "不存在的令牌报错退出"
check "不存在的令牌给出提示" 'printf "%s" "$OUT" | grep -q "令牌不存在"'

echo "== 备份"
( set -a; . "$SAFE_TEST_ROOT/etc/safe/safe.env"; set +a; SAFE_HOME="$SAFE_TEST_ROOT/var/lib/safe" SAFE_CONF="$SAFE_TEST_ROOT/etc/safe" \
	sh "$SAFE_TEST_ROOT/opt/safe/backup.sh" "$SAFE_TEST_ROOT/var/backups/safe" >/dev/null )
ARCHIVE=$(ls "$SAFE_TEST_ROOT"/var/backups/safe/safe-*.tar.gz 2>/dev/null | head -1)
check "备份包含数据库、CA 和配置" 'tar -tzf "$ARCHIVE" | grep -q "safe.db" && tar -tzf "$ARCHIVE" | grep -q "pki/ca.key" && tar -tzf "$ARCHIVE" | grep -q "conf/safe.env"'

echo "== 卸载"
OUT=$(curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/agent.sh" | SAFE_ACTION=uninstall sh 2>&1) || true
check "Agent 卸载" '[ ! -f "$SAFE_TEST_ROOT/usr/local/bin/safe-agent" ] && ! systemctl is-active --quiet safe-agent'
curl -fsSLk --pinnedpubkey "$PIN" "$NODE_URL/install/probe.sh" | SAFE_ACTION=uninstall sh >/dev/null 2>&1 || true
sh "$BUNDLE/install.sh" uninstall >/dev/null 2>&1
check "管理中心卸载后保留数据" '[ ! -d "$SAFE_TEST_ROOT/opt/safe" ] && [ -f "$SAFE_TEST_ROOT/var/lib/safe/pki/ca.key" ]'
sh "$BUNDLE/install.sh" uninstall --purge >/dev/null 2>&1
check "--purge 删除全部数据" '[ ! -d "$SAFE_TEST_ROOT/var/lib/safe" ] && [ ! -d "$SAFE_TEST_ROOT/etc/safe" ]'

echo
echo "通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" = 0 ]
