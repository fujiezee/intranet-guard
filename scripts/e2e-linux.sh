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

step "环境"
echo "    $(. /etc/os-release && echo "$PRETTY_NAME")，内核 $(uname -r)"
echo "    sleep：$(readlink -f "$(command -v sleep)")（$(ls -l "$(readlink -f "$(command -v sleep)")" | awk '{print $5}') 字节）"

step "准备隔离测试用的网络命名空间"
# 隔离主机会切断所有网络，不能在 CI 机器本身上做：在独立的网络命名空间里运行第二个 Agent 来测试。
# 必须在安装管理中心之前创建，管理中心证书才会包含 10.200.0.1 / 10.200.0.3。
command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null
ip netns add safeiso
ip link add veth-safe type veth peer name veth-ns
ip link set veth-ns netns safeiso
ip addr add 10.200.0.1/29 dev veth-safe
ip addr add 10.200.0.3/29 dev veth-safe
ip link set veth-safe up
ip netns exec safeiso ip addr add 10.200.0.2/29 dev veth-ns
ip netns exec safeiso ip link set veth-ns up
ip netns exec safeiso ip link set lo up
ok "命名空间 safeiso（10.200.0.2）↔ 主机（10.200.0.1 管理中心，10.200.0.3 普通服务）"

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
mkdir -p /var/www/html # 让 Webshell 监控和自检有网站目录可用
AT=$(api POST /enroll-tokens '{"kind":"agent","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
PT=$(api POST /enroll-tokens '{"kind":"probe","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/agent.sh" | SAFE_ENROLL_TOKEN="$AT" SAFE_AGENT_ID=ci-agent sh
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/probe.sh" | SAFE_ENROLL_TOKEN="$PT" SAFE_PROBE_ID=ci-probe sh
wait_for "Agent 在线" 60 "api GET /agents | json '[a for a in d if a[\"id\"]==\"ci-agent\" and a[\"status\"]==\"online\"][0]'"
[ ! -s /etc/safe-agent.env ] && ok "注册后令牌已从节点配置中删除"
api GET /agents | json '[a for a in d if a["id"]=="ci-agent"][0]["capabilities"]' | grep -q exec_monitor && ok "命令审计已启用（进程连接器）" || fail "命令审计未启用"
[ "$(systemctl show -p CPUQuotaPerSecUSec --value safe-agent)" = 200ms ] && ok "Agent 资源上限生效（CPU 20%）" || fail "Agent CPU 上限未生效"

step "扫描"
TASK=$(api POST /tasks '{"probe_id":"ci-probe","targets":["127.0.0.1"],"ports":[443,8443]}' | json 'd["id"]')
wait_for "探针完成扫描任务" 60 "api GET /tasks/$TASK | json 'd[\"status\"]' | grep -qx done"

step "蜜罐"
api PUT /honeypots/ci-probe '{"enabled":true,"services":[{"type":"http","port":18088},{"type":"ssh","port":12222}],"ignore_sources":[]}' >/dev/null
wait_for "探针上的蜜罐开始监听" 60 "api GET /honeypots | json '[h for h in d if h[\"probe_id\"]==\"ci-probe\" and h[\"status\"].get(\"18088\")==\"listening\"][0]'"
# 用 127.0.0.2 作为来源模拟另一台主机（探针本机地址的访问会被忽略）
curl -fsS --interface 127.0.0.2 -o /dev/null http://127.0.0.1:18088/admin || true
curl -sS --interface 127.0.0.2 -o /dev/null -d 'username=admin&password=Passw0rd' http://127.0.0.1:18088/login # 蜜罐会返回 401
wait_for "蜜罐访问产生高危告警，关联到来源 127.0.0.2" 30 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"honeypot\" and a[\"ip\"]==\"127.0.0.2\" and a[\"severity\"]==\"high\"][0]'"
curl -fsS -o /dev/null http://127.0.0.1:18088/ || true
sleep 5
[ "$(api GET /honeypot-events | json 'len([e for e in d if e["src_ip"]=="127.0.0.1"])')" = 0 ] && ok "探针本机地址的访问不告警"
wait_for "蜜罐告警归入来源主机的事件（侦察探测阶段）" 10 \
	"api GET /incidents | json '[i for i in d if i[\"ip\"]==\"127.0.0.2\" and \"discovery\" in i[\"stages\"]][0]'"

step "攻击模拟自检"
api POST /simulations '{"agent_id":"ci-agent","scenarios":["fim","process","honeypot","reverse_shell","download_exec","webshell"]}' >/dev/null
wait_for "自检全部结束" 240 "api GET /simulations | json 'all(s[\"status\"] not in (\"pending\",\"running\") for s in d)' | grep -qx True"
api GET /simulations | json '"\n".join("    %s %-9s %s %s" % (s["scenario"], s["status"], s.get("latency_ms",0), s.get("detail","")) for s in d)'
[ "$(api GET /simulations | json 'sum(s["status"]=="passed" for s in d)')" = 6 ] || fail "自检未全部通过"
ok "文件篡改、临时目录执行、访问蜜罐、反弹 shell、下载并执行、Webshell 6 个场景全部检出"
wait_for "自检产物已自动清理" 150 "! ls /etc/cron.d/safe-simulation-* /tmp/safe-sim-* /var/www/html/safe-sim-* 2>/dev/null | grep -q ."
[ "$(api GET '/alerts?status=open' | json 'len([a for a in d if "sim-" in a["message"]])')" = 0 ] && ok "自检告警已自动关闭"
[ "$(api GET /alerts | json 'len([a for a in d if "sim-" in a["message"] and a.get("incident_id")])')" = 0 ] && ok "自检告警不形成事件"

step "Agent 停止"
systemctl stop safe-agent
wait_for "停止 Agent 产生「Agent 被停止」告警，状态为已停止" 20 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"agent_stopped\"][0]' && api GET /agents | json '[a for a in d if a[\"id\"]==\"ci-agent\"][0][\"status\"]' | grep -qx stopped"
systemctl start safe-agent
wait_for "重新启动后恢复在线" 40 "api GET /agents | json '[a for a in d if a[\"id\"]==\"ci-agent\"][0][\"status\"]' | grep -qx online"

step "处置：封禁 IP"
# 封禁命名空间的地址 10.200.0.2（管理中心拒绝封禁回环地址），从命名空间里验证无法访问主机
action() { api POST /actions "$1" | json 'd["id"]'; }
action_status() { api GET /actions | json "[a for a in d if a['id']=='$1'][0]['status']"; }
ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "封禁前 10.200.0.2 可以访问主机"
api POST /actions '{"agent_id":"ci-agent","type":"block_ip","params":{"ip":"127.0.0.3"},"reason":"e2e"}' >/dev/null 2>&1 &&
	fail "允许了封禁回环地址" || ok "拒绝封禁回环地址"
ID=$(action '{"agent_id":"ci-agent","type":"block_ip","params":{"ip":"10.200.0.2","duration":"600"},"reason":"e2e"}')
wait_for "封禁完成" 60 "action_status $ID | grep -qx done"
api GET /actions | json "[a for a in d if a['id']=='$ID'][0]['result']" | sed 's/^/    /'
! ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "10.200.0.2 已被封禁" || fail "封禁未生效"
curl -sk -m 3 -o /dev/null "$CONSOLE/" && ok "其他来源不受影响"
UNDO=$(api POST "/actions/$ID/rollback" '{"reason":"e2e"}' | json 'd["id"]')
wait_for "撤销封禁完成" 60 "action_status $UNDO | grep -qx done"
ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "解除后恢复访问" || fail "解除未生效"
[ "$(action_status "$ID")" = rolled_back ] && ok "原封禁动作标记为已撤销"

step "处置：结束进程、隔离文件"
sleep 600 &
VICTIM=$!
EXE=$(readlink /proc/$VICTIM/exe)
ID=$(action "{\"agent_id\":\"ci-agent\",\"type\":\"kill_process\",\"params\":{\"pid\":\"$VICTIM\",\"exe\":\"$EXE\"},\"reason\":\"e2e\"}")
wait_for "结束进程完成" 60 "action_status $ID | grep -qx done"
! kill -0 $VICTIM 2>/dev/null && ok "进程 $VICTIM 已结束" || fail "进程仍在运行"
echo '<?php @eval($_POST["c"]); ?>' >/var/www/html/evil.php
ID=$(action '{"agent_id":"ci-agent","type":"quarantine_file","params":{"path":"/var/www/html/evil.php"},"reason":"e2e"}')
wait_for "隔离文件完成" 60 "action_status $ID | grep -qx done"
[ ! -e /var/www/html/evil.php ] && [ -f "/var/lib/safe-agent/quarantine/$ID/file" ] && ok "文件已移入隔离区" || fail "文件未隔离"
UNDO=$(api POST "/actions/$ID/rollback" '{"reason":"e2e"}' | json 'd["id"]')
wait_for "恢复文件完成" 60 "action_status $UNDO | grep -qx done"
grep -q eval /var/www/html/evil.php && ok "文件已恢复到原位置" && rm -f /var/www/html/evil.php

step "处置：隔离主机（命名空间中的第二个 Agent，需两人审批）"
NT=$(api POST /enroll-tokens '{"kind":"agent","max_uses":1,"ttl_hours":1}' | json 'd["token"]')
mkdir -p /var/lib/safe-agent-ns
ip netns exec safeiso env SAFE_ENROLL_TOKEN="$NT" /usr/local/bin/safe-agent -server https://10.200.0.1:8443 -id ns-agent \
	-state /var/lib/safe-agent-ns/state.json -interval 5s -web-dirs "" >/var/log/safe-agent-ns.log 2>&1 &
NS_AGENT=$!
wait_for "命名空间中的 Agent 在线" 60 "api GET /agents | json '[a for a in d if a[\"id\"]==\"ns-agent\" and a[\"status\"]==\"online\"][0]'"
ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "隔离前可以访问 10.200.0.3"
ID=$(action '{"agent_id":"ns-agent","type":"isolate_host","reason":"e2e"}')
[ "$(action_status "$ID")" = awaiting_approval ] && ok "隔离主机等待审批"
api POST "/actions/$ID/approve" >/dev/null 2>&1 && fail "发起人自己批准了" || ok "发起人不能自己批准"
api POST /users '{"username":"admin2","password":"second-admin-pw","role":"admin"}' >/dev/null
TOKEN2=$(curl -fsSk -X POST "$CONSOLE/api/v1/auth/login" -d '{"username":"admin2","password":"second-admin-pw"}' | json 'd["token"]')
curl -fsSk -X POST -H "Authorization: Bearer $TOKEN2" "$CONSOLE/api/v1/actions/$ID/approve" && ok "第二位管理员批准"
wait_for "隔离完成" 60 "action_status $ID | grep -qx done"
! ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "隔离后无法访问其他地址" || fail "隔离未生效"
SEEN1=$(api GET /agents | json '[a for a in d if a["id"]=="ns-agent"][0]["last_seen"]')
sleep 12
SEEN2=$(api GET /agents | json '[a for a in d if a["id"]=="ns-agent"][0]["last_seen"]')
[ "$SEEN1" != "$SEEN2" ] && ok "隔离期间仍与管理中心保持通信（可接收解除指令）" || fail "隔离后 Agent 失联"
UNDO=$(api POST "/actions/$ID/rollback" '{"reason":"e2e"}' | json 'd["id"]')
wait_for "解除隔离完成" 60 "action_status $UNDO | grep -qx done"
ip netns exec safeiso curl -sk -m 3 -o /dev/null https://10.200.0.3/ && ok "解除后恢复访问" || fail "解除隔离未生效"
kill $NS_AGENT 2>/dev/null || true
ip netns del safeiso
ip link del veth-safe 2>/dev/null || true

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
