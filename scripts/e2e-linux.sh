#!/bin/sh
# 真实 Linux（systemd + root）上的端到端测试，CI 使用：sudo scripts/e2e-linux.sh dist/safe-<版本>-linux-amd64.tar.gz
# 流程：一键安装管理中心 → 一行命令装 Agent / 探针 → 扫描 → 蜜罐真实访问 → 攻击模拟自检全部通过 → 升级 → 卸载。
# 会修改本机系统（创建用户、systemd 服务、/etc/cron.d 等），只应在一次性的 CI 机器或测试虚拟机上运行。
set -eu

BUNDLE_TGZ=${1:?用法：sudo $0 dist/safe-<版本>-linux-amd64.tar.gz [在线升级测试用的程序目录]}
UPGRADE_DIR=${2:-} # 含 safe-agent-next（新版本）和 safe-agent-broken（启动即退出的坏版本），见 CI
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
# 预先建好 eve.json，安装脚本会让探针读取它：先写入按 Suricata 格式构造的记录（心跳等需要长时间的场景），
# 之后再启动真实的 Suricata 写入同一文件
mkdir -p /var/log/suricata && : >/var/log/suricata/eve.json
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

step "值守工作台与报表"
INC=$(api GET /duty/queue | json '[i for i in d if i["kind"]=="incident" and i["ip"]=="127.0.0.2"][0]["id"]')
[ -n "$INC" ] && ok "蜜罐事件进入待办队列（带响应时限）" || fail "待办队列中没有蜜罐事件"
api PATCH "/incidents/$INC" '{"assignee":"admin","status":"investigating"}' >/dev/null
api GET /duty/queue | json "[i for i in d if i['id']==$INC and i['kind']=='incident'][0]['acked_at']" >/dev/null && ok "认领后记录响应时间" || fail "认领没有记录响应时间"
[ "$(api GET '/duty/metrics?range=today' | json 'd["mtta_samples"] >= 1')" = True ] && ok "平均响应时长计入认领" || fail "平均响应时长没有计入认领"
[ "$(api POST /duty/handovers '{"note":"e2e"}' | json 'd["summary"]["open_total"] >= 1')" = True ] && ok "交接班汇总遗留待办" || fail "交接班没有汇总遗留待办"
wait_for "启动后生成最近一份日报和周报" 70 "api GET /reports | json 'len({r[\"kind\"] for r in d}) == 2 or exit(1)'"

step "威胁情报与外联分析（合成的 Suricata 记录）"
EVE=/var/log/suricata/eve.json
ts() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%S.000000+0000; }
api POST /intel/indicators '{"text":"c2.e2e-test.example\n203.0.113.77","severity":"high","note":"e2e"}' >/dev/null
VER=$(api GET /intel | json 'len(d["indicators"])')
[ "$VER" = 2 ] && ok "导入 2 条情报"
grep -q -- "-eve /var/log/suricata/eve.json" /etc/systemd/system/safe-probe.service && ok "探针读取完整的 eve.json"
wait_for "探针加载情报（日志）" 40 "journalctl -u safe-probe --no-pager | grep -q 'threat intel loaded.*indicators=3'"
NOW=$(date +%s)
{
	printf '{"timestamp":"%s","event_type":"dns","src_ip":"10.9.0.5","src_port":5353,"dest_ip":"10.9.0.53","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"www.c2.e2e-test.example","rrtype":"A"}}\n' "$(ts $NOW)"
	printf '{"timestamp":"%s","event_type":"flow","src_ip":"10.9.0.6","src_port":40000,"dest_ip":"203.0.113.77","dest_port":443,"proto":"TCP","flow":{"bytes_toserver":900,"start":"%s"}}\n' "$(ts $NOW)" "$(ts $NOW)"
	# 每 60 秒一次、略有抖动的连接：C2 心跳
	for i in $(seq 0 14); do
		t=$((NOW - 1800 + i * 60 + (i % 3) - 1))
		printf '{"timestamp":"%s","event_type":"flow","src_ip":"10.9.0.7","src_port":%d,"dest_ip":"198.51.100.99","dest_port":8443,"proto":"TCP","flow":{"bytes_toserver":300,"start":"%s"}}\n' "$(ts $t)" $((41000 + i)) "$(ts $t)"
	done
} >>"$EVE"
wait_for "查询情报域名 → 威胁情报告警（关联 10.9.0.5）" 30 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"threat_intel\" and a[\"ip\"]==\"10.9.0.5\" and \"c2.e2e-test.example\" in a[\"message\"]][0]'"
wait_for "连接情报地址 → 威胁情报告警（关联 10.9.0.6）" 30 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"threat_intel\" and a[\"ip\"]==\"10.9.0.6\"][0]'"
wait_for "固定间隔连接 → C2 心跳告警（探针每分钟评估一次）" 100 \
	"api GET /alerts | json '[a for a in d if a[\"type\"]==\"c2_beacon\" and a[\"ip\"]==\"10.9.0.7\"][0]'"
wait_for "情报命中归入“命令控制”阶段的事件" 10 \
	"api GET /incidents | json '[i for i in d if i[\"ip\"]==\"10.9.0.5\" and \"c2\" in i[\"stages\"]][0]'"

step "威胁情报（真实 Suricata 抓包）"
# 在出口网卡上运行软件源中的 Suricata，与探针共用同一个 eve.json：验证真实输出格式能被解析、真实流量能被检出。
# 临时把 Cloudflare 的公共 DNS（无害、稳定可达）作为情报，再真实访问它。DNS 与 TLS 用不同域名：
# 同一主机对同一域名的多次命中会去重成一条告警，同一个域名无法分别验证两条路径。
IFACE=$(ip route show default | awk '{print $5; exit}')
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata >/dev/null 2>&1 ||
	{ apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata >/dev/null; }
systemctl stop suricata 2>/dev/null || true # 软件包自带的服务：停掉，改用下面明确指定网卡和参数的进程
# -k none：云主机网卡有校验和卸载，抓到的出站包校验和尚未计算，不关闭校验会丢弃这些流
suricata -D -i "$IFACE" -k none -l /var/log/suricata --pidfile /run/safe-e2e-suricata.pid >/var/log/safe-e2e-suricata.log 2>&1
echo "    $(suricata -V 2>&1 | head -1)，网卡 $IFACE"
sleep 3
[ -s /run/safe-e2e-suricata.pid ] && kill -0 "$(cat /run/safe-e2e-suricata.pid)" 2>/dev/null ||
	{ cat /var/log/safe-e2e-suricata.log /var/log/suricata/suricata.log 2>/dev/null | tail -30; fail "Suricata 未能启动"; }
# flow_id 只出现在 Suricata 自己输出的记录里（上面构造的记录没有）
wait_for "Suricata 开始写入 eve.json" 60 "grep -q '\"flow_id\"' /var/log/suricata/eve.json"
api POST /intel/indicators '{"text":"one.one.one.one\ncloudflare-dns.com\n1.1.1.1","severity":"medium","note":"e2e 真实抓包"}' >/dev/null
wait_for "探针加载新情报" 40 "journalctl -u safe-probe --no-pager | grep -q 'threat intel loaded.*indicators=6'"
getent hosts one.one.one.one >/dev/null || true # 只解析，不连接：验证 DNS 路径
# 不经 DNS、直接连 1.1.1.1，SNI 为 cloudflare-dns.com：验证 TLS 路径与流记录（IP）路径
curl -sS -m 10 -o /dev/null --resolve cloudflare-dns.com:443:1.1.1.1 https://cloudflare-dns.com/ || true
HOSTIP=$(ip -4 -o addr show "$IFACE" | awk '{split($4,a,"/"); print a[1]; exit}')
intel_alert() { api GET /alerts | json "[a for a in d if a['type']=='threat_intel' and a['ip']=='$HOSTIP' and '$1' in a['message']][0]"; }
wait_for "真实 DNS 查询 one.one.one.one → 威胁情报告警" 60 "intel_alert '查询了情报中的域名 one.one.one.one'"
wait_for "真实 TLS 连接（SNI cloudflare-dns.com）→ 威胁情报告警" 60 "intel_alert 'SNI）情报中的域名 cloudflare-dns.com'"
# 流记录在连接结束并超时后才输出（Suricata 默认关闭状态的 TCP 流约 60 秒）
wait_for "真实连接 1.1.1.1 的流记录 → 威胁情报告警" 180 "intel_alert '1.1.1.1:443'"
grep '"flow_id"' /var/log/suricata/eve.json | grep -m1 '"event_type":"dns"' | python3 -c 'import sys,json;d=json.load(sys.stdin)["dns"];print("    DNS 记录格式：version=%s type=%s" % (d.get("version",2), d.get("type")))' || true
# 这段时间里 CI 机器的正常出站流量（软件下载、GitHub 通信）不应被误判
FP=$(api GET /alerts | json "len([a for a in d if a['ip']=='$HOSTIP' and a['type'] in ('dns_anomaly','c2_beacon','exfiltration')])")
[ "$FP" = 0 ] && ok "CI 机器的正常流量没有产生 DGA / 隧道 / 心跳 / 外传误报" || { api GET /alerts | json "[a['message'] for a in d if a['ip']=='$HOSTIP']"; fail "正常流量产生了 $FP 条误报"; }

step "攻击模拟自检"
api POST /simulations '{"agent_id":"ci-agent","scenarios":["fim","process","honeypot","reverse_shell","download_exec","webshell"]}' >/dev/null
# 情报自检：Agent 通过系统解析器真实查询自检域名，经出口网卡被 Suricata 看到
SIM=$(api POST /simulations '{"agent_id":"ci-agent","scenarios":["intel_dns"]}' | json 'd[0]["id"]')
wait_for "情报命中自检通过（Agent 真实发出的 DNS 查询）" 150 "api GET /simulations | json '[s for s in d if s[\"id\"]==\"$SIM\" and s[\"status\"]==\"passed\"][0]'"
wait_for "自检全部结束" 240 "api GET /simulations | json 'all(s[\"status\"] not in (\"pending\",\"running\") for s in d)' | grep -qx True"
api GET /simulations | json '"\n".join("    %s %-9s %s %s" % (s["scenario"], s["status"], s.get("latency_ms",0), s.get("detail","")) for s in d)'
[ "$(api GET /simulations | json 'sum(s["status"]=="passed" for s in d)')" = 7 ] || fail "自检未全部通过"
ok "文件篡改、临时目录执行、访问蜜罐、反弹 shell、下载并执行、Webshell、情报命中 7 个场景全部检出"
wait_for "自检产物已自动清理" 150 "! ls /etc/cron.d/safe-simulation-* /tmp/safe-sim-* /var/www/html/safe-sim-* 2>/dev/null | grep -q ."
[ "$(api GET '/alerts?status=open' | json 'len([a for a in d if "sim-" in a["message"]])')" = 0 ] && ok "自检告警已自动关闭"
[ "$(api GET /alerts | json 'len([a for a in d if "sim-" in a["message"] and a.get("incident_id")])')" = 0 ] && ok "自检告警不形成事件"

if [ -n "$UPGRADE_DIR" ]; then
	step "控制台在线升级 Agent"
	DL=/opt/safe/downloads
	agent_ver() { api GET /agents | json "[a for a in d if a['id']=='ci-agent'][0]['version']"; }
	up_state() { api GET /upgrades | json "[a['upgrade'] for a in d['agents'] if a['id']=='ci-agent'][0]$1"; }
	[ "$(agent_ver)" = ci ] && ok "当前 Agent 版本 ci（打包时写入的版本号）"
	[ -L /usr/local/bin/safe-agent ] && [ -x /var/lib/safe-agent/bin/safe-agent ] && ok "Agent 程序位于可写的状态目录（/usr/local/bin 下为链接）"
	cp /opt/safe/downloads/safe-agent-linux-amd64 "$WORK/agent-ci"
	install -m 755 "$UPGRADE_DIR/safe-agent-next" "$DL/safe-agent-linux-amd64"
	install -m 644 "$UPGRADE_DIR/safe-agent-next.sig" "$DL/safe-agent-linux-amd64.sig"
	echo '{"version": "ci-next"}' >"$DL/manifest.json"
	[ "$(api GET /upgrades | json 'd["latest"]["version"]')" = ci-next ] && ok "管理中心识别到新版本 ci-next"
	api POST /upgrades '{"agent_ids":["ci-agent"]}' >/dev/null
	wait_for "Agent 升级到 ci-next" 120 "[ \"\$(agent_ver)\" = ci-next ]"
	wait_for "升级状态为成功" 30 "up_state \"['state']\" | grep -qx succeeded"
	systemctl is-active --quiet safe-agent && ok "服务运行中"
	[ ! -e /var/lib/safe-agent/bin/safe-agent.prev ] && [ ! -e /var/lib/safe-agent/upgrade-pending ] && ok "确认后旧程序和待确认记录已清理"
	journalctl -u safe-agent --no-pager | grep -q "agent upgrade completed" && ok "日志记录升级完成"

	install -m 755 "$UPGRADE_DIR/safe-agent-broken" "$DL/safe-agent-linux-amd64"
	install -m 644 "$UPGRADE_DIR/safe-agent-broken.sig" "$DL/safe-agent-linux-amd64.sig"
	echo '{"version": "ci-broken"}' >"$DL/manifest.json"
	api POST /upgrades '{"agent_ids":["ci-agent"]}' >/dev/null
	wait_for "坏版本（能通过自检、运行即退出）被自动回退，升级状态为失败" 180 "up_state \"['state']\" | grep -qx failed"
	up_state "['detail']" | sed 's/^/    /'
	up_state "['detail']" | grep -q 自动回退 && ok "失败原因：自动回退"
	wait_for "Agent 以原版本 ci-next 恢复在线" 60 \
		"[ \"\$(agent_ver)\" = ci-next ] && api GET /agents | json \"[a for a in d if a['id']=='ci-agent'][0]['status']\" | grep -qx online"
	# 还原，后续步骤使用原版本
	install -m 755 "$WORK/agent-ci" "$DL/safe-agent-linux-amd64"
	echo '{"version": "ci"}' >"$DL/manifest.json"
fi

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
