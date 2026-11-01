#!/bin/sh
# Kubernetes 端到端测试，CI 使用：sudo scripts/e2e-k8s.sh dist/safe-<版本>-linux-amd64.tar.gz
# 在本机安装管理中心和单节点 k3s，按控制台给出的命令以 DaemonSet 部署 Agent，在业务 Pod 中执行
# 真实的攻击动作并检查告警能定位到 Pod。会修改本机系统，只应在一次性的 CI 机器或测试虚拟机上运行。
set -eu

BUNDLE_TGZ=${1:?用法：sudo $0 dist/safe-<版本>-linux-amd64.tar.gz [在线升级测试用的程序目录]}
UPGRADE_DIR=${2:-}
[ "$(id -u)" = 0 ] || { echo "需要 root"; exit 1; }
K3S_VERSION=v1.31.4+k3s1
WORK=$(mktemp -d)
tar -xzf "$BUNDLE_TGZ" -C "$WORK"
BUNDLE=$(echo "$WORK"/safe-*)
CONSOLE=https://127.0.0.1
NODE=https://127.0.0.1:8443 # DaemonSet 使用 hostNetwork，节点本机地址即可访问管理中心
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

step "安装管理中心"
OUT=$("$BUNDLE/install.sh" 2>&1) || { echo "$OUT"; fail "install.sh 失败"; }
ADMIN_PW=$(echo "$OUT" | sed -n 's/^ *密码： *\([A-Za-z0-9]*\).*/\1/p')
TOKEN=$(curl -fsSk -X POST "$CONSOLE/api/v1/auth/login" -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" | json 'd["token"]')
[ -n "$TOKEN" ] && ok "管理中心已安装并登录"
PIN=$(api GET /install-info | json 'd["pin"]')

step "安装 k3s（单节点 Kubernetes ${K3S_VERSION}）"
# 不启用 k3s 自带的 Traefik / ServiceLB：它们通过端口映射占用节点的 80 / 443，会截走发往本机管理控制台（443）的请求
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - --write-kubeconfig-mode 644 \
	--disable traefik --disable servicelb >/dev/null 2>&1
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
wait_for "节点就绪" 180 "kubectl get nodes | grep -qw Ready"
NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
echo "    节点 ${NODE_NAME}，$(kubectl version 2>/dev/null | grep -i server | head -1)"

step "按控制台给出的命令部署 Agent（DaemonSet）"
AT=$(api POST /enroll-tokens '{"kind":"agent","max_uses":2,"ttl_hours":1,"note":"k8s e2e"}' | json 'd["token"]')
kubectl create namespace safe-system >/dev/null
kubectl -n safe-system create secret generic safe-enroll --from-literal=token="$AT" >/dev/null
curl -fsSLk --pinnedpubkey "$PIN" "$NODE/install/agent-k8s.yaml" | kubectl apply -f - | sed 's/^/    /'
agent_field() { api GET /agents | json "[a for a in d if a['id']=='$NODE_NAME'][0]$1"; }
diag() {
	echo "    管理中心 /agents 返回："
	api GET /agents | head -c 600 || echo "    （请求失败）"
	echo
	kubectl get pods -A -o wide || true
	kubectl -n safe-system describe pods | tail -30 || true
	kubectl -n safe-system logs -l app=safe-agent --all-containers --tail=50 || true
}
i=0
until [ "$(agent_field "['status']" 2>/dev/null)" = online ]; do
	i=$((i + 3))
	[ $i -le 300 ] || { diag; fail "Agent 未上线"; }
	sleep 3
done
ok "节点 $NODE_NAME 的 Agent 在线（${i} 秒，含镜像拉取）"
agent_field "['capabilities']" | grep -q exec_monitor && ok "命令审计已启用（DaemonSet 中通过 nsenter 运行在节点命名空间）" ||
	{ diag; fail "命令审计未启用"; }
[ "$(kubectl -n safe-system get ds safe-agent -o jsonpath='{.status.numberReady}')" = 1 ] && ok "DaemonSet 就绪 1/1"

step "业务 Pod 中的攻击行为"
kubectl run victim --image=alpine:3.20 --restart=Never --command -- sleep 3600 >/dev/null
wait_for "业务 Pod 就绪" 120 "kubectl wait --for=condition=Ready pod/victim --timeout=5s"
# 每条命令后保留 sleep：让 Agent 在进程存活期间读到命令行
kubectl exec victim -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null; sleep 3' || true
kubectl exec victim -- sh -c 'nsenter -t 1 -m -- true 2>/dev/null; sleep 3' || true
# 交互式终端：用 script 提供伪终端，相当于运维执行 kubectl exec -it
script -qec "kubectl exec -it victim -- sh -c 'sleep 3; true'" /dev/null >/dev/null || true
pod_alert() { api GET /alerts | json "[a for a in d if a['type']=='suspicious_command' and '[$1]' in a['message'] and 'Pod default/victim' in a['message']][0]"; }
wait_for "读取 ServiceAccount 令牌 → 告警，定位到 Pod default/victim" 60 "pod_alert '读取 K8s 凭据'"
wait_for "容器内 nsenter -t 1 → 容器逃逸告警" 60 "pod_alert '容器逃逸迹象'"
wait_for "kubectl exec -it → 容器内交互式 shell 告警" 60 "pod_alert '容器内交互式 shell'"
api GET /alerts | json "[a['message'] for a in d if 'Pod default/victim' in a['message']][0]" | cut -c1-200 | sed 's/^/    /'
# 节点上的系统组件（k3s、containerd、CoreDNS 等）在这段时间的正常活动不应产生容器告警
FP=$(api GET /alerts | json "len([a for a in d if a['type']=='suspicious_command' and 'Pod ' in a['message'] and 'default/victim' not in a['message']])")
[ "$FP" = 0 ] && ok "集群系统组件没有产生容器告警" ||
	{ api GET /alerts | json "[a['message'][:200] for a in d if 'Pod ' in a['message']]"; fail "系统组件产生了 $FP 条容器告警"; }

step "攻击模拟自检（DaemonSet 中的 Agent）"
api POST /simulations "{\"agent_id\":\"$NODE_NAME\",\"scenarios\":[\"fim\",\"process\",\"reverse_shell\",\"download_exec\"]}" >/dev/null
wait_for "自检全部结束" 240 "api GET /simulations | json 'all(s[\"status\"] not in (\"pending\",\"running\") for s in d)' | grep -qx True"
api GET /simulations | json '"\n".join("    %s %-9s %s %s" % (s["scenario"], s["status"], s.get("latency_ms",0), s.get("detail","")) for s in d)'
[ "$(api GET /simulations | json 'sum(s["status"]=="passed" for s in d)')" = 4 ] || fail "自检未全部通过"
ok "文件篡改、临时目录执行、反弹 shell、下载并执行 4 个场景全部检出"

if [ -n "$UPGRADE_DIR" ]; then
	step "控制台在线升级 DaemonSet 中的 Agent"
	DL=/opt/safe/downloads
	restarts() { kubectl -n safe-system get pods -l app=safe-agent -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}'; }
	R0=$(restarts)
	cp "$DL/safe-agent-linux-amd64" "$WORK/agent-ci"
	install -m 755 "$UPGRADE_DIR/safe-agent-next" "$DL/safe-agent-linux-amd64"
	install -m 644 "$UPGRADE_DIR/safe-agent-next.sig" "$DL/safe-agent-linux-amd64.sig"
	echo '{"version": "ci-next"}' >"$DL/manifest.json"
	api POST /upgrades "{\"agent_ids\":[\"$NODE_NAME\"]}" >/dev/null
	wait_for "Agent 升级到 ci-next" 180 "[ \"\$(agent_field \"['version']\")\" = ci-next ]"
	[ "$(restarts)" -gt "$R0" ] && ok "容器重启为新版本（Pod 未重建，重启 $(restarts) 次）"
	[ "$(kubectl -n safe-system get ds safe-agent -o jsonpath='{.status.numberReady}')" = 1 ] && ok "DaemonSet 仍然就绪"
	wait_for "升级状态为成功" 30 "api GET /upgrades | json \"[a['upgrade']['state'] for a in d['agents'] if a['id']=='$NODE_NAME'][0]\" | grep -qx succeeded"
	install -m 755 "$WORK/agent-ci" "$DL/safe-agent-linux-amd64"
	echo '{"version": "ci"}' >"$DL/manifest.json"
fi

step "Pod 重建：不需要令牌"
kubectl -n safe-system delete secret safe-enroll >/dev/null
kubectl -n safe-system delete pod -l app=safe-agent --wait=true >/dev/null
wait_for "删除 Pod 时上报「Agent 被停止」" 30 "api GET /alerts | json '[a for a in d if a[\"type\"]==\"agent_stopped\" and \"$NODE_NAME\" in a[\"message\"]][0]'"
wait_for "DaemonSet 重建后恢复在线（Secret 已删除，使用节点上保存的证书）" 120 "[ \"\$(agent_field \"['status']\")\" = online ]"
[ "$(api GET /enroll-tokens | json "[t for t in d if t['note']=='k8s e2e'][0]['uses']")" = 1 ] && ok "令牌只使用了一次"

step "卸载"
kubectl delete namespace safe-system --wait=true >/dev/null
wait_for "删除命名空间后 Agent 状态为已停止" 60 "[ \"\$(agent_field \"['status']\")\" = stopped ]"

printf '\n通过 %d 项\n' "$PASS"
