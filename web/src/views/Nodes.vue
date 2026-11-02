<template>
  <div>
    <div class="page-header">
      <h2>{{ t('节点管理') }}</h2>
      <div class="tools">
        <el-button @click="load">{{ t('刷新') }}</el-button>
        <el-button type="primary" @click="openDialog">{{ t('生成注册令牌') }}</el-button>
      </div>
    </div>

    <el-card shadow="never" :header="t('已注册节点（{p0}）', { p0: nodes.length })">
      <el-table :data="nodes" size="small" stripe :empty-text="t('还没有节点通过证书注册')">
        <el-table-column :label="t('类型')" width="80">
          <template #default="{ row }">{{ row.kind === 'probe' ? t('探针') : 'Agent' }}</template>
        </el-table-column>
        <el-table-column prop="id" :label="t('节点 ID')" min-width="160" />
        <el-table-column :label="t('状态')" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'active' ? 'success' : 'info'">{{ row.status === 'active' ? t('有效') : t('已吊销') }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('证书到期')" width="170">
          <template #default="{ row }">
            <span :class="{ warn: row.status === 'active' && daysLeft(row) < 30 }">{{ formatTime(row.cert_expiry) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('注册时间')" width="170"><template #default="{ row }">{{ formatTime(row.enrolled_at) }}</template></el-table-column>
        <el-table-column :label="t('证书序列号')" min-width="160"><template #default="{ row }"><span class="mono sub">{{ row.serial }}</span></template></el-table-column>
        <el-table-column :label="t('操作')" width="80">
          <template #default="{ row }">
            <el-button v-if="row.status === 'active'" size="small" link type="danger" @click="revoke(row)">{{ t('吊销') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px" :header="t('注册令牌')">
      <el-table :data="tokens" size="small" stripe :empty-text="t('暂无令牌')">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column :label="t('类型')" width="80">
          <template #default="{ row }">{{ row.kind === 'probe' ? t('探针') : 'Agent' }}</template>
        </el-table-column>
        <el-table-column :label="t('已用 / 上限')" width="110"><template #default="{ row }">{{ row.uses }} / {{ row.max_uses }}</template></el-table-column>
        <el-table-column :label="t('过期时间')" width="170">
          <template #default="{ row }">
            <span :class="{ sub: expired(row) }">{{ formatTime(row.expires_at) }}{{ expired(row) ? t('（已过期）') : '' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="note" :label="t('备注')" min-width="160" />
        <el-table-column prop="created_by" :label="t('创建人')" width="100" />
        <el-table-column :label="t('操作')" width="80">
          <template #default="{ row }"><el-button size="small" link type="danger" @click="removeToken(row)">{{ t('删除') }}</el-button></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialog" :title="t('生成注册令牌')" width="560px" @closed="created = null">
      <template v-if="!created">
        <el-form :model="form" label-width="90px">
          <el-form-item :label="t('节点类型')">
            <el-radio-group v-model="form.kind">
              <el-radio value="agent">{{ t('主机 Agent') }}</el-radio>
              <el-radio value="probe">{{ t('网络探针') }}</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item :label="t('可用次数')"><el-input-number v-model="form.max_uses" :min="1" :max="10000" /></el-form-item>
          <el-form-item :label="t('有效期')">
            <el-input-number v-model="form.ttl_hours" :min="1" :max="720" />
            <span class="hint">{{ t('小时') }}</span>
          </el-form-item>
          <el-form-item :label="t('备注')"><el-input v-model="form.note" :placeholder="t('例如：生产环境 Web 集群批量部署')" /></el-form-item>
        </el-form>
      </template>
      <template v-else>
        <el-alert type="warning" :closable="false" show-icon :title="t('令牌只显示这一次，请立即复制保存')" style="margin-bottom: 12px" />
        <el-input :model-value="created.token" readonly class="mono">
          <template #append><el-button @click="copy(created.token)">{{ t('复制') }}</el-button></template>
        </el-input>
        <template v-if="created.kind === 'probe'">
          <p class="hint-block">{{ t('网段名（探针 ID，用于下发扫描任务）：') }}</p>
          <el-input v-model="probeID" :placeholder="t('例如 office-3f')" style="margin-bottom: 4px" />
          <el-alert v-if="!probeIDValid" type="warning" :closable="false" show-icon style="margin-bottom: 4px"
            :title="t('填写网段名后显示安装命令（字母、数字、. _ -，以字母或数字开头）')" />
        </template>
        <p class="hint-block">{{ t('管理中心地址（节点用这个地址下载程序和连接管理中心，必须是节点能访问到的地址）：') }}</p>
        <el-input v-model="server" :placeholder="t('https://管理中心IP或域名:8443')" style="margin-bottom: 4px" />
        <el-alert v-if="!serverValid" type="error" :closable="false" show-icon :title="t('地址格式应为 https://IP或域名:端口')" style="margin-bottom: 4px" />
        <el-alert v-else-if="serverLoopback" type="error" :closable="false" show-icon style="margin-bottom: 4px"
          :title="t('localhost / 127.0.0.1 只指向节点自己，节点无法用它连接管理中心，请改成管理中心的 IP 或域名')" />
        <el-alert v-else-if="serverNote" type="warning" :closable="false" show-icon :title="serverNote" style="margin-bottom: 4px" />
        <el-radio-group v-if="created.kind === 'agent'" v-model="platform" size="small" style="margin-top: 8px">
          <el-radio-button value="linux">Linux</el-radio-button>
          <el-radio-button value="windows">Windows</el-radio-button>
          <el-radio-button value="k8s">Kubernetes</el-radio-button>
        </el-radio-group>
        <p v-if="k8s" class="hint-block">
          {{ t('在能执行 kubectl 的机器上运行（为每个节点部署一个 Agent，包括之后新加入的节点）。令牌使用次数需不少于节点数，当前为') }} <b>{{ created.max_uses }}</b>：
        </p>
        <p v-else-if="windows" class="hint-block">
          {{ t('在每台要接入的 Windows 服务器上，以管理员身份打开') }} <b>Windows PowerShell</b>{{ t('（5.1，不是 PowerShell 7），粘贴执行（自动下载、开启安全审计、注册并安装为系统服务）：') }}
        </p>
        <p v-else class="hint-block">
          {{ t('在{p0}上执行（自动下载、注册并作为系统服务运行；支持 systemd、sysvinit 和 OpenRC）：', { p0: created.kind === 'probe' ? t('探针机器') : t('每台要接入的服务器') }) }}
        </p>
        <div class="cmd-wrap">
          <pre class="cmd">{{ installCommand }}</pre>
          <el-button size="small" class="cmd-copy" @click="copy(installCommand)">{{ t('复制命令') }}</el-button>
        </div>
        <el-alert v-if="installInfo && !binaryAvailable" type="warning" :closable="false" show-icon style="margin-top: 8px"
          :title="t('管理中心没有提供节点安装程序（开发环境未使用安装包部署），这条命令会下载失败；请用 make release 生成的安装包部署管理中心。')" />
        <p class="hint-block">
          {{ t('命令固定了管理中心的公钥指纹，即使中间人冒充管理中心也无法替换下载内容；令牌中的 CA 指纹则用于注册时再次校验。') }}
          <template v-if="k8s">{{ t('需要特权容器、hostPID 和 hostNetwork（与节点上直接安装的 Agent 行为相同，可看到所有容器内执行的命令）；镜像 curlimages/curl、debian:bookworm-slim 来自 Docker Hub，内网环境请同步到内部仓库。注册完成后可删除 Secret。') }}</template>
          <template v-else-if="windows">{{ t('支持 Windows Server 2012 R2 及以上；同一令牌可用于多台服务器（不超过令牌的使用次数）。') }}</template>
          <template v-else>{{ t('要求目标服务器的 curl ≥ 7.39（CentOS 7 等过旧系统请改用离线安装）。') }}</template>
        </p>
      </template>
      <template #footer>
        <template v-if="!created">
          <el-button @click="dialog = false">{{ t('取消') }}</el-button>
          <el-button type="primary" @click="submit">{{ t('生成') }}</el-button>
        </template>
        <el-button v-else type="primary" @click="dialog = false">{{ t('完成') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { formatTime } from '../format'

const nodes = ref([])
const tokens = ref([])
const dialog = ref(false)
const created = ref(null)
const form = reactive({ kind: 'agent', max_uses: 1, ttl_hours: 24, note: '' })

const daysLeft = (n) => (new Date(n.cert_expiry) - Date.now()) / 86400000
const expired = (t) => new Date(t.expires_at) < Date.now() || t.uses >= t.max_uses

const installInfo = ref(null)
const probeID = ref('')
// 与管理中心的节点 ID 校验一致（validNodeID）
const probeIDValid = computed(() => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(probeID.value.trim()))
const platform = ref('linux')
const windows = computed(() => created.value?.kind === 'agent' && platform.value === 'windows')
const k8s = computed(() => created.value?.kind === 'agent' && platform.value === 'k8s')
const binaryAvailable = computed(() =>
  installInfo.value?.available.some((f) => f.startsWith(windows.value ? 'safe-agent-windows-' : `safe-${created.value?.kind}-linux-`)),
)

// 安装命令中的管理中心地址：配置的正式地址（-node-urls）→ 浏览器地址栏的主机名 →
// 用 localhost 打开控制台时换成本机的局域网地址（命令里写 localhost 的话，节点会连到它自己）
const server = ref('')
const serverNote = ref('')
const loopback = (h) => ['localhost', '127.0.0.1', '::1', '[::1]'].includes(h)
const serverHost = computed(() => {
  try {
    return new URL(server.value).hostname
  } catch {
    return ''
  }
})
const serverValid = computed(() => /^https:\/\/[A-Za-z0-9.\-]+(:\d{1,5})?$|^https:\/\/\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/.test(server.value.trim()))
const serverLoopback = computed(() => loopback(serverHost.value))

function defaultServer(info) {
  serverNote.value = ''
  if (info.node_urls.length) {
    if (info.node_urls.length > 1) serverNote.value = t('已配置 {p0} 个管理中心实例，全部实例都会写入节点配置，连接失败时自动切换', { p0: info.node_urls.length })
    return info.node_urls[0]
  }
  if (!loopback(location.hostname)) return `https://${location.hostname}:${info.node_port}`
  const ip = info.addresses.find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a)) || info.addresses[0]
  if (!ip) return `https://${location.hostname}:${info.node_port}`
  serverNote.value = t('你用 localhost 打开了控制台，命令中已换成本机地址 {p0}；如果节点应通过域名或其他地址访问，请修改（也可用启动参数 -node-urls 固定）', { p0: ip })
  return `https://${ip}:${info.node_port}`
}

const installCommand = computed(() => {
  if (!created.value || !installInfo.value || !serverValid.value || serverLoopback.value) return ''
  const { kind, token } = created.value
  const base = server.value.trim()
  if (windows.value) return installInfo.value.windows_command.replace('__TOKEN__', token).replace('__HOSTPORT__', new URL(base).host)
  if (k8s.value) {
    return [
      'kubectl create namespace safe-system',
      `kubectl -n safe-system create secret generic safe-enroll --from-literal=token='${token}'`,
      `curl -fsSLk --pinnedpubkey '${installInfo.value.pin}' ${base}/install/agent-k8s.yaml | kubectl apply -f -`,
    ].join('\n')
  }
  // 令牌（和网段名）在地址里，由管理中心写进脚本：命令以 | sudo sh 结尾，不用在 sudo 后面拼环境变量
  if (kind === 'probe' && !probeIDValid.value) return ''
  const query = kind === 'probe' ? `?id=${probeID.value.trim()}` : ''
  return `curl -fsSLk --pinnedpubkey '${installInfo.value.pin}' '${base}/i/${token}${query}' | sudo sh`
})

async function load() {
  const [n, t] = await Promise.all([api.nodes(), api.enrollTokens()])
  nodes.value = n
  tokens.value = t
}

function openDialog() {
  Object.assign(form, { kind: 'agent', max_uses: 1, ttl_hours: 24, note: '' })
  created.value = null
  dialog.value = true
}

async function submit() {
  ;[created.value, installInfo.value] = await Promise.all([api.createEnrollToken({ ...form }), api.installInfo()])
  server.value = defaultServer(installInfo.value)
  probeID.value = ''
  load()
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('已复制'))
  } catch {
    ElMessage.warning(t('浏览器不允许自动复制，请手动选中复制'))
  }
}

async function revoke(row) {
  try {
    await ElMessageBox.confirm(t('吊销后 {p0} 的证书立即失效，节点需要用新令牌重新注册。确定吊销？', { p0: row.id }), t('吊销节点'), { type: 'warning' })
  } catch {
    return
  }
  await api.revokeNode(row.kind, row.id)
  ElMessage.success(t('已吊销'))
  load()
}

async function removeToken(row) {
  await api.deleteEnrollToken(row.id)
  load()
}

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.sub { color: #909399; font-size: 12px; }
.warn { color: #e6a23c; font-weight: 500; }
.hint { margin-left: 8px; color: #909399; }
.hint-block { color: #606266; font-size: 13px; margin: 12px 0 6px; }
.cmd-wrap { position: relative; }
.cmd-copy { position: absolute; top: 6px; right: 6px; }
.cmd { padding-right: 90px !important; background: #1f2d3d; color: #e5eaf3; padding: 12px; border-radius: 4px; font-size: 12px; white-space: pre-wrap; word-break: break-all; margin: 0; }
</style>
