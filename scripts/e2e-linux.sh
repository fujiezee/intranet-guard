#!/bin/sh
# 真实 Linux（systemd + root）上的端到端测试，CI 使用：sudo scripts/e2e-linux.sh dist/safe-<版本>-linux-amd64.tar.gz
# 流程：一键安装管理中心 → 一行命令装 Agent / 探针 → 扫描 → 蜜罐真实访问 → 攻击模拟自检全部通过 → 升级 → 卸载。
# 会修改本机系统（创建用户、systemd 服务、/etc/cron.d 等），只应在一次性的 CI 机器或测试虚拟机上运行。
set -eu

BUNDLE_TGZ=${1:?用法：sudo $0 dist/safe-<版本>-linux-amd64.tar.gz}
[ "$(id -u)" = 0 ] || { echo "需要 root"; exit 1; }
WORK=$(mktemp -d)
tar -xzf "$BUNDLE_TGZ" -C "$WORK"
BUNDLE=$(echo "$WORK"/safe-*)
CONSOLE=https://127.0.0.1
NODE=https://127.0.0.1:8443
PASS=0

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
api() { curl -fsSk -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$CONSOLE/api/v1$2" ${3:+-d "$3"}; }
# wait_for 描述 超时秒数 条件命令
wait_for() {
	i=0
	until eval "$3" >/dev/null 2>&1; do
		i=$((i + 2))
		[ $i -le "$2" ] || fail "$1（等待 $2 秒超时）"
		sleep 2
	done
	ok "$1（${i} 秒）"
}

step "一键安装管理中心"
OUT=$("$BUNDLE/install.sh" 2>&1) || { echo "$OUT"; fail "install.sh 失败"; }
echo "$OUT" | sed 's/^/    /'
ADMIN_PW=$(echo "$OUT" | sed -n 's/^ *密码： *\([A-Za-z0-9]*\).*/\1/p')
[ -n "$ADMIN_PW" ] || fail "没有打印管理员密码"
systemctl is-active --quiet safe-server && ok "safe-server 以 systemd 服务运行"
[ "$(ps -o user= -p "$(systemctl show -p MainPID --value safe-server)")" = safe ] && ok "以非 root 的 safe 用户运行" || fail "safe-server 没有以 safe 用户运行"
TOKEN=$(curl -fsSk -X POST "$CONSOLE/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | json 'd["token"]')
[ -n "$TOKEN" ] && ok "用打印的密码登录控制台（HTTPS 443）"
PIN=$(api GET /install-info | json 'd["pin"]')

step "一行命令安装 Agent 和探针"
AT=$(api POST /enroll-tokens '{"kind":"agent","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
PT=$(api POST /enroll-tokens '{"kind":"probe","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/agent.sh" | SAFE_ENROLL_TOKEN="$AT" SAFE_AGENT_ID=ci-agent sh
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/probe.sh" | SAFE_ENROLL_TOKEN="$PT" SAFE_PROBE_ID=ci-probe sh
wait_for "Agent 在线" 60 "api GET /agents | json '[a for a in d if a[\"id\"]==\"ci-agent\" and a[\"status\"]==\"online\"][0]'"
[ ! -s /etc/safe-agent.env ] && ok "注册后令牌已从节点配置中删除"

step "扫描"
TASK=$(api POST /tasks '{"probe_id":"ci-probe","targets":["127.0.0.1"],"ports":[443,8443]}' | json 'd["id"]')
wait_for "探针完成扫描任务" 60 "api GET /tasks/$TASK | json 'd[\"status\"]' | grep -qx done"

step "蜜罐"
api PUT /honeypots/ci-probe '{"enabled":true,"services":[{"type":"http","port":18088},{"type":"ssh","port":12222}],"ignore_sources":[]}' >/dev/null
wait_for "探针上的蜜罐开始监听" 60 "api GET /honeypots | json '[h for h in d if h[\"probe_id\"]==\"ci-probe\" and h[\"status\"].get(\"18088\")==\"listening\"][0]'"
# 用 127.0.0.2 作为来源模拟另一台主机（探针本机地址的访问会被忽略）
curl -fsS --interface 127.0.0.2 -o /dev/null http://127.0.0.1:18088/admin || true
curl -fsS --interface 127.0.0.2 -o /dev/null -d 'username=admin&password=Passw0rd' http://127.0.0.1:18088/login || true
wait_for "蜜罐访问产生高危告警，关联到来源 127.0.0.2" 30 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"honeypot\" and a[\"ip\"]==\"127.0.0.2\" and a[\"severity\"]==\"high\"][0]'"
curl -fsS -o /dev/null http://127.0.0.1:18088/ || true
sleep 5
[ "$(api GET /honeypot-events | json 'len([e for e in d if e["src_ip"]=="127.0.0.1"])')" = 0 ] && ok "探针本机地址的访问不告警"

step "攻击模拟自检"
api POST /simulations '{"agent_id":"ci-agent","scenarios":["fim","process","honeypot"]}' >/dev/null
wait_for "自检全部结束" 240 "api GET /simulations | json 'all(s[\"status\"] not in (\"pending\",\"running\") for s in d)' | grep -qx True"
api GET /simulations | json '"\n".join("    %s %-9s %s %s" % (s["scenario"], s["status"], s.get("latency_ms",0), s.get("detail","")) for s in d)'
[ "$(api GET /simulations | json 'sum(s["status"]=="passed" for s in d)')" = 3 ] || fail "自检未全部通过"
ok "文件篡改、临时目录执行、访问蜜罐 3 个场景全部检出"
wait_for "自检产物已自动清理" 150 "! ls /etc/cron.d/safe-simulation-* /tmp/safe-sim-* 2>/dev/null | grep -q ."
[ "$(api GET '/alerts?status=open' | json 'len([a for a in d if "sim-" in a["message"]])')" = 0 ] && ok "自检告警已自动关闭"

step "升级"
OUT=$("$BUNDLE/install.sh" 2>&1) || { echo "$OUT"; fail "升级失败"; }
echo "$OUT" | grep -q "升级完成" && ok "再次执行 install.sh 为升级"
curl -fsSk -X POST "$CONSOLE/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" -o /dev/null && ok "原密码仍可登录"
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/agent.sh" | sh >/dev/null && ok "Agent 免令牌升级"

step "备份"
( set -a; . /etc/safe/safe.env; set +a; SAFE_HOME=/var/lib/safe SAFE_CONF=/etc/safe /opt/safe/backup.sh /var/backups/safe >/dev/null )
tar -tzf "$(ls -t /var/backups/safe/safe-*.tar.gz | head -1)" | grep -q pki/ca.key && ok "备份包含 CA"

step "卸载"
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/agent.sh" | SAFE_ACTION=uninstall sh >/dev/null
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/probe.sh" | SAFE_ACTION=uninstall sh >/dev/null
"$BUNDLE/install.sh" uninstall --purge >/dev/null
! systemctl is-active --quiet safe-server && ! systemctl is-active --quiet safe-agent && ! systemctl is-active --quiet safe-probe &&
	[ ! -d /var/lib/safe ] && ok "全部卸载干净"

printf '\n\033[32m通过 %d 项\033[0m\n' "$PASS"
rm -rf "$WORK"
