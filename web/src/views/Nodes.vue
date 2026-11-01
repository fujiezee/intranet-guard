<template>
  <div>
    <div class="page-header">
      <h2>节点管理</h2>
      <div class="tools">
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="openDialog">生成注册令牌</el-button>
      </div>
    </div>

    <el-card shadow="never" :header="`已注册节点（${nodes.length}）`">
      <el-table :data="nodes" size="small" stripe empty-text="还没有节点通过证书注册">
        <el-table-column label="类型" width="80">
          <template #default="{ row }">{{ row.kind === 'probe' ? '探针' : 'Agent' }}</template>
        </el-table-column>
        <el-table-column prop="id" label="节点 ID" min-width="160" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'active' ? 'success' : 'info'">{{ row.status === 'active' ? '有效' : '已吊销' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="证书到期" width="170">
          <template #default="{ row }">
            <span :class="{ warn: row.status === 'active' && daysLeft(row) < 30 }">{{ formatTime(row.cert_expiry) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="注册时间" width="170"><template #default="{ row }">{{ formatTime(row.enrolled_at) }}</template></el-table-column>
        <el-table-column label="证书序列号" min-width="160"><template #default="{ row }"><span class="mono sub">{{ row.serial }}</span></template></el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button v-if="row.status === 'active'" size="small" link type="danger" @click="revoke(row)">吊销</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px" header="注册令牌">
      <el-table :data="tokens" size="small" stripe empty-text="暂无令牌">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column label="类型" width="80">
          <template #default="{ row }">{{ row.kind === 'probe' ? '探针' : 'Agent' }}</template>
        </el-table-column>
        <el-table-column label="已用 / 上限" width="110"><template #default="{ row }">{{ row.uses }} / {{ row.max_uses }}</template></el-table-column>
        <el-table-column label="过期时间" width="170">
          <template #default="{ row }">
            <span :class="{ sub: expired(row) }">{{ formatTime(row.expires_at) }}{{ expired(row) ? '（已过期）' : '' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="note" label="备注" min-width="160" />
        <el-table-column prop="created_by" label="创建人" width="100" />
        <el-table-column label="操作" width="80">
          <template #default="{ row }"><el-button size="small" link type="danger" @click="removeToken(row)">删除</el-button></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialog" title="生成注册令牌" width="560px" @closed="created = null">
      <template v-if="!created">
        <el-form :model="form" label-width="90px">
          <el-form-item label="节点类型">
            <el-radio-group v-model="form.kind">
              <el-radio value="agent">主机 Agent</el-radio>
              <el-radio value="probe">网络探针</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="可用次数"><el-input-number v-model="form.max_uses" :min="1" :max="10000" /></el-form-item>
          <el-form-item label="有效期">
            <el-input-number v-model="form.ttl_hours" :min="1" :max="720" />
            <span class="hint">小时</span>
          </el-form-item>
          <el-form-item label="备注"><el-input v-model="form.note" placeholder="例如：生产环境 Web 集群批量部署" /></el-form-item>
        </el-form>
      </template>
      <template v-else>
        <el-alert type="warning" :closable="false" show-icon title="令牌只显示这一次，请立即复制保存" style="margin-bottom: 12px" />
        <el-input :model-value="created.token" readonly class="mono">
          <template #append><el-button @click="copy(created.token)">复制</el-button></template>
        </el-input>
        <template v-if="created.kind === 'probe'">
          <p class="hint-block">网段名（探针 ID，用于下发扫描任务）：</p>
          <el-input v-model="probeID" placeholder="例如 office-3f" style="margin-bottom: 4px" />
        </template>
        <el-radio-group v-if="created.kind === 'agent'" v-model="platform" size="small" style="margin-top: 8px">
          <el-radio-button value="linux">Linux</el-radio-button>
          <el-radio-button value="windows">Windows</el-radio-button>
        </el-radio-group>
        <p v-if="windows" class="hint-block">
          在每台要接入的 Windows 服务器上，以管理员身份打开 <b>Windows PowerShell</b>（5.1，不是 PowerShell 7），粘贴执行
          （自动下载、开启安全审计、注册并安装为系统服务）：
        </p>
        <p v-else class="hint-block">
          在{{ created.kind === 'probe' ? '探针机器' : '每台要接入的服务器' }}上以 root 执行（自动下载、注册并作为系统服务运行）：
        </p>
        <div class="cmd-wrap">
          <pre class="cmd">{{ installCommand }}</pre>
          <el-button size="small" class="cmd-copy" @click="copy(installCommand)">复制命令</el-button>
        </div>
        <el-alert v-if="installInfo && !binaryAvailable" type="warning" :closable="false" show-icon style="margin-top: 8px"
          title="管理中心没有提供节点安装程序（开发环境未使用安装包部署），这条命令会下载失败；请用 make release 生成的安装包部署管理中心。" />
        <p class="hint-block">
          命令固定了管理中心的公钥指纹，即使中间人冒充管理中心也无法替换下载内容；
          令牌中的 CA 指纹则用于注册时再次校验。
          <template v-if="windows">支持 Windows Server 2012 R2 及以上；同一令牌可用于多台服务器（不超过令牌的使用次数）。</template>
          <template v-else>要求目标服务器的 curl ≥ 7.39（CentOS 7 等过旧系统请改用离线安装）。</template>
        </p>
      </template>
      <template #footer>
        <template v-if="!created">
          <el-button @click="dialog = false">取消</el-button>
          <el-button type="primary" @click="submit">生成</el-button>
        </template>
        <el-button v-else type="primary" @click="dialog = false">完成</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
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
const platform = ref('linux')
const windows = computed(() => created.value?.kind === 'agent' && platform.value === 'windows')
const binaryAvailable = computed(() =>
  installInfo.value?.available.some((f) => f.startsWith(windows.value ? 'safe-agent-windows-' : `safe-${created.value?.kind}-linux-`)),
)

const installCommand = computed(() => {
  if (!created.value || !installInfo.value) return ''
  const { kind, token } = created.value
  if (windows.value) return installInfo.value.windows_command.replace('__TOKEN__', token)
  const server = `https://${location.hostname}:${installInfo.value.node_port}`
  const env = [`SAFE_ENROLL_TOKEN='${token}'`]
  if (kind === 'probe') env.push(`SAFE_PROBE_ID='${probeID.value.trim() || '<网段名>'}'`)
  return `curl -fsSLk --pinnedpubkey '${installInfo.value.pin}' ${server}/install/${kind}.sh | sudo ${env.join(' ')} sh`
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
  probeID.value = ''
  load()
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('浏览器不允许自动复制，请手动选中复制')
  }
}

async function revoke(row) {
  try {
    await ElMessageBox.confirm(`吊销后 ${row.id} 的证书立即失效，节点需要用新令牌重新注册。确定吊销？`, '吊销节点', { type: 'warning' })
  } catch {
    return
  }
  await api.revokeNode(row.kind, row.id)
  ElMessage.success('已吊销')
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
