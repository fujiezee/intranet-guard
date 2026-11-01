#!/bin/sh
# 规模与高可用演练：两个管理中心实例共用 PostgreSQL + ClickHouse，用 safe-loadtest 模拟大量 Agent 上报，
# 中途强制杀掉一个实例，检查接入不中断、后台任务切换、告警推送不漏。CI 使用：
#   scripts/e2e-ha.sh <bin 目录> <PostgreSQL DSN> <ClickHouse DSN>
# 可用环境变量调整规模：AGENTS（默认 10000）、INTERVAL（30s）、DURATION（180s）、EVENTS（每次上报平均事件数，30）、
# ALERT_EVERY（平均每多少次上报带一条告警，100）。
set -eu

BIN=${1:?用法：$0 <bin 目录> <postgres://...> <clickhouse://...>}
PG=${2:?}
CH=${3:?}
AGENTS=${AGENTS:-10000}
INTERVAL=${INTERVAL:-30s}
DURATION=${DURATION:-180s}
EVENTS=${EVENTS:-30}
W=$(mktemp -d)
PASS=0
PW=ha-admin-password

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() {
	printf '  \033[31m✗\033[0m %s\n' "$*"
	for f in "$W/a.log" "$W/b.log" "$W/loadtest.log"; do
		[ -f "$f" ] && { echo "--- $(basename "$f")（最后 20 行）"; tail -20 "$f"; }
	done
	exit 1
}
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
secs() { echo "${1%s}"; }
wait_for() {
	i=0
	until eval "$3" >/dev/null 2>&1; do
		i=$((i + 1))
		[ $i -le "$2" ] || fail "$1（等待 $2 秒超时）"
		sleep 1
	done
	ok "$1（${i} 秒）"
}
start_instance() { # 名称 控制台端口 节点端口
	SAFE_INIT_ADMIN_PASSWORD=$PW "$BIN/safe-server" -addr "127.0.0.1:$2" -node-addr ":$3" -db "$PG" -events-db "$CH" \
		-pki-dir "$W/pki" -node-urls https://127.0.0.1:18443,https://127.0.0.1:18444 >"$W/$1.log" 2>&1 &
	echo $! >"$W/$1.pid"
}
cleanup() {
	for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done
}
trap cleanup EXIT

command -v psql >/dev/null || { sudo apt-get install -y -qq postgresql-client >/dev/null; }

step "环境"
echo "    $(nproc 2>/dev/null || sysctl -n hw.ncpu) 核；文件描述符上限 $(ulimit -n)"
echo "    模拟 Agent ${AGENTS} 个，上报周期 ${INTERVAL}，每次平均 ${EVENTS} 个事件，持续 ${DURATION}"

step "启动两个管理中心实例"
start_instance a 18080 18443
wait_for "实例 A 启动" 60 "curl -s -o /dev/null http://127.0.0.1:18080/api/v1/auth/me" # 收到任何 HTTP 响应即已启动
wait_for "实例 A 成为主实例（执行后台任务）" 15 "grep -q 'became leader' $W/a.log"
start_instance b 18081 18444 # 与 A 共用 CA 和服务端私钥（同一个 pki 目录；实际部署时复制到各实例）
wait_for "实例 B 启动" 60 "curl -s -o /dev/null http://127.0.0.1:18081/api/v1/auth/me"
sleep 8
grep -q 'became leader' "$W/b.log" && fail "两个实例同时成为主实例" || ok "实例 B 为备用（不执行后台任务）"

# 告警推送接收端：记录每次推送的告警 ID
cat >"$W/hook.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
out = open(sys.argv[1], "a", buffering=1)
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        for a in body.get("alerts", []):
            out.write("%d\n" % a["id"])
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 18999), H).serve_forever()
EOF
python3 "$W/hook.py" "$W/pushed.txt" &
echo $! >"$W/hook.pid"
TOKEN=$(curl -fsS -X POST http://127.0.0.1:18081/api/v1/auth/login -d "{\"username\":\"admin\",\"password\":\"$PW\"}" | json 'd["token"]')
api() { curl -fsS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "http://127.0.0.1:18081/api/v1$2" ${3:+-d "$3"}; }
api POST /notify-channels '{"name":"ha-hook","type":"webhook","url":"http://127.0.0.1:18999/","min_severity":"low","enabled":true}' >/dev/null
ok "两个实例共用数据：在实例 B 上登录（用户由 A 创建）并配置推送渠道"

step "压测，中途强制杀掉实例 A"
SAFE_LOADTEST_PASSWORD=$PW "$BIN/safe-loadtest" -console http://127.0.0.1:18080 \
	-nodes https://127.0.0.1:18443,https://127.0.0.1:18444 -agents "$AGENTS" -interval "$INTERVAL" -duration "$DURATION" \
	-events "$EVENTS" -alert-every "${ALERT_EVERY:-100}" -max-p99 3s >"$W/loadtest.log" 2>&1 &
LT=$!
wait_for "全部 Agent 注册完成" 600 "grep -q 'enrollment finished' $W/loadtest.log"
grep 'enrollment finished' "$W/loadtest.log" | sed 's/^.*INFO /    /'
# 预热一个周期 + 持续时间的一半后杀掉 A（kill -9：模拟宕机，不做任何清理）
sleep $(($(secs "$INTERVAL") + $(secs "$DURATION") / 2))
kill -9 "$(cat "$W/a.pid")"
KILLED=$(date +%s)
ok "已强制杀掉实例 A（$(date +%T)）"
wait_for "实例 B 接管后台任务" 30 "grep -q 'became leader' $W/b.log"
LT_STATUS=0
wait $LT || LT_STATUS=$?
grep progress "$W/loadtest.log" | sed 's/^.*INFO progress /    /'
sed -n '/^{/,/^}/p' "$W/loadtest.log" | tee "$W/summary.json" | sed 's/^/    /'
[ "$LT_STATUS" = 0 ] && ok "压测达标：错误率 < 1%，p99 < 3 秒（含切换过程）" || fail "压测未达标（见上方结果）"
SWITCHED=$(grep -c 'switched to another instance' "$W/loadtest.log" || true)
[ "$SWITCHED" -gt 0 ] && ok "${SWITCHED} 个 Agent 连接失败后自动切换到实例 B" || fail "Agent 没有切换实例"

step "切换后的数据完整性"
ONLINE=$(api GET /agents | json "sum(1 for a in d if a['status']=='online' and a['id'].startswith('load'))")
[ "$ONLINE" -ge "$AGENTS" ] && ok "全部 ${ONLINE} 个 Agent 在线（经实例 B 上报）" || fail "只有 $ONLINE 个 Agent 在线"
wait_for "告警推送跟上（没有待推送的告警）" 120 \
	"[ \"\$(psql '$PG' -tAc 'SELECT count(*) FROM alerts WHERE NOT notified')\" = 0 ]"
DB=$(psql "$PG" -tAc "SELECT count(*) FROM alerts WHERE type = 'webshell'")
ACCEPTED=$(json 'd["alert_events_accepted"]' <"$W/summary.json")
PUSHED=$(($(sort -u "$W/pushed.txt" | wc -l)))
TOTAL=$(($(wc -l <"$W/pushed.txt")))
sort -u "$W/pushed.txt" >"$W/pushed.sorted"
psql "$PG" -tAc "SELECT id FROM alerts WHERE type = 'webshell'" | sort -u >"$W/db.sorted"
MISSING=$(($(comm -23 "$W/db.sorted" "$W/pushed.sorted" | wc -l)))
echo "    压测侧被接受的告警事件 ${ACCEPTED}，数据库中的告警 ${DB}，推送 ${TOTAL} 次（去重后 ${PUSHED}）"
[ "$DB" -gt 0 ] || fail "压测没有产生告警，无法检查推送"
[ "$DB" -ge "$ACCEPTED" ] && ok "被接受的上报全部生成了告警（没有因切换丢失）" || fail "数据库告警 $DB 少于被接受的 $ACCEPTED"
[ "$MISSING" = 0 ] && ok "所有告警都已推送（切换过程中没有漏推）" || fail "$MISSING 条告警没有推送"
DUP=$((TOTAL - PUSHED))
echo "    重复推送 ${DUP} 次（切换瞬间可能发生：宁可重复不漏推）"

printf '\n通过 %d 项\n' "$PASS"
