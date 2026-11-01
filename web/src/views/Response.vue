<template>
  <div>
    <div class="page-header">
      <h2>{{ t('处置') }}</h2>
      <div class="tools">
        <el-button @click="load">{{ t('刷新') }}</el-button>
        <el-button v-if="auth.isAdmin" type="danger" @click="openDialog()">{{ t('新建处置') }}</el-button>
      </div>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px"
      :title="t('处置由主机上的 Agent 执行（需 Linux、root）。封禁、隔离文件、隔离主机都可以一键撤销；隔离主机需要另一位管理员批准。所有操作记入审计。')" />

    <el-table :data="actions" v-loading="loading" stripe :empty-text="t('还没有处置记录')">
      <el-table-column :label="t('时间')" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column prop="agent_id" :label="t('主机')" width="130" />
      <el-table-column :label="t('动作')" width="110">
        <template #default="{ row }">{{ typeLabels[row.type] || row.type }}</template>
      </el-table-column>
      <el-table-column :label="t('参数')" min-width="180">
        <template #default="{ row }"><span class="mono sub">{{ paramText(row) }}</span></template>
      </el-table-column>
      <el-table-column :label="t('状态')" width="100">
        <template #default="{ row }"><el-tag size="small" :type="statusMap[row.status]?.type">{{ statusMap[row.status]?.label || row.status }}</el-tag></template>
      </el-table-column>
      <el-table-column :label="t('原因 / 结果')" min-width="260">
        <template #default="{ row }">
          <div>{{ row.reason }}</div>
          <div v-if="row.result" class="sub">{{ row.result }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('发起 / 批准')" width="130">
        <template #default="{ row }">{{ row.created_by }}<span v-if="row.approved_by" class="sub"> / {{ row.approved_by }}</span></template>
      </el-table-column>
      <el-table-column v-if="auth.isAdmin" :label="t('操作')" width="100">
        <template #default="{ row }">
          <el-button v-if="row.status === 'awaiting_approval' && row.created_by !== auth.user?.username" size="small" type="danger" @click="approve(row)">{{ t('批准') }}</el-button>
          <span v-else-if="row.status === 'awaiting_approval'" class="sub">{{ t('待他人批准') }}</span>
          <el-button v-if="row.status === 'done' && undoable[row.type]" size="small" link type="primary" @click="rollback(row)">{{ t('撤销') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialog" :title="t('新建处置')" width="560px">
      <el-form :model="form" label-width="90px">
        <el-form-item :label="t('主机')">
          <el-select v-model="form.agent_id" filterable :placeholder="t('选择 Agent')" style="width: 100%">
            <el-option v-for="a in agents" :key="a.id" :label="t('{p0}（{p1}）{p2}', { p0: a.id, p1: a.ips.join(', '), p2: a.status === 'online' ? '' : t(' 离线') })" :value="a.id" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('动作')">
          <el-radio-group v-model="form.type">
            <el-radio v-for="t in creatable" :key="t" :value="t">{{ typeLabels[t] }}</el-radio>
          </el-radio-group>
        </el-form-item>
        <template v-if="form.type === 'block_ip'">
          <el-form-item :label="t('封禁 IP')"><el-input v-model="form.ip" :placeholder="t('例如攻击来源 10.6.6.6')" /></el-form-item>
          <el-form-item :label="t('时长')">
            <el-select v-model="form.duration" style="width: 160px">
              <el-option :label="t('1 小时')" value="3600" />
              <el-option :label="t('1 天')" value="86400" />
              <el-option :label="t('7 天')" value="604800" />
              <el-option :label="t('30 天')" value="2592000" />
            </el-select>
            <span class="hint">{{ t('到期自动解除') }}</span>
          </el-form-item>
        </template>
        <template v-if="form.type === 'kill_process'">
          <el-form-item label="PID"><el-input v-model="form.pid" /></el-form-item>
          <el-form-item :label="t('程序路径')"><el-input v-model="form.exe" :placeholder="t('/tmp/.x/kworker（防止误杀 PID 被复用的进程）')" /></el-form-item>
        </template>
        <el-form-item v-if="form.type === 'quarantine_file'" :label="t('文件路径')">
          <el-input v-model="form.path" placeholder="/var/www/html/upload/x.php" />
        </el-form-item>
        <template v-if="form.type === 'isolate_host'">
          <el-form-item :label="t('额外允许')">
            <el-input v-model="form.allow" :placeholder="t('可选，逗号分隔，如取证用的跳板机 10.0.0.5')" />
          </el-form-item>
          <el-alert type="warning" :closable="false" show-icon style="margin: -6px 0 16px"
            :title="t('隔离后主机只能与管理中心、DNS 和上面的地址通信，业务将中断（包括已建立的连接）。需要另一位管理员批准后执行，可随时撤销。')" />
        </template>
        <el-form-item :label="t('原因')"><el-input v-model="form.reason" type="textarea" :rows="2" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">{{ t('取消') }}</el-button>
        <el-button type="danger" :loading="submitting" @click="submit">{{ t('提交') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const typeLabels = {
  block_ip: t('封禁 IP'),
  unblock_ip: t('解除封禁'),
  kill_process: t('结束进程'),
  quarantine_file: t('隔离文件'),
  restore_file: t('恢复文件'),
  isolate_host: t('隔离主机'),
  release_host: t('解除隔离'),
}
const creatable = ['block_ip', 'kill_process', 'quarantine_file', 'isolate_host']
const undoable = { block_ip: true, quarantine_file: true, isolate_host: true }
const statusMap = {
  awaiting_approval: { label: t('待批准'), type: 'warning' },
  pending: { label: t('待执行'), type: 'info' },
  sent: { label: t('执行中'), type: 'warning' },
  done: { label: t('已完成'), type: 'success' },
  failed: { label: t('失败'), type: 'danger' },
  expired: { label: t('已作废'), type: 'info' },
  rolled_back: { label: t('已撤销'), type: 'info' },
}

const route = useRoute()
const actions = ref([])
const agents = ref([])
const loading = ref(false)
const dialog = ref(false)
const submitting = ref(false)
const form = reactive({ agent_id: '', type: 'block_ip', ip: '', duration: '86400', pid: '', exe: '', path: '', allow: '', reason: '' })

function paramText(a) {
  const p = a.params || {}
  switch (a.type) {
    case 'block_ip':
      return t('{p0}，{p1} 小时', { p0: p.ip, p1: Math.round(p.duration / 3600) })
    case 'unblock_ip':
      return p.ip
    case 'kill_process':
      return `PID ${p.pid} ${p.exe}`
    case 'quarantine_file':
      return p.path
    case 'isolate_host':
      return p.allow ? t('允许 {p0}', { p0: p.allow }) : ''
    default:
      return a.rollback_of ? t('撤销 {p0}', { p0: a.rollback_of }) : ''
  }
}

async function load() {
  loading.value = true
  try {
    ;[actions.value, agents.value] = await Promise.all([api.actions(), api.agents()])
  } finally {
    loading.value = false
  }
}

function openDialog(prefill = {}) {
  Object.assign(form, { agent_id: '', type: 'block_ip', ip: '', duration: '86400', pid: '', exe: '', path: '', allow: '', reason: '' }, prefill)
  dialog.value = true
}

async function submit() {
  const params = {
    block_ip: { ip: form.ip.trim(), duration: form.duration },
    kill_process: { pid: form.pid.trim(), exe: form.exe.trim() },
    quarantine_file: { path: form.path.trim() },
    isolate_host: { allow: form.allow.trim() },
  }[form.type]
  submitting.value = true
  try {
    const a = await api.createAction({ agent_id: form.agent_id, type: form.type, params, reason: form.reason })
    ElMessage.success(a.status === 'awaiting_approval' ? t('已提交，等待另一位管理员批准') : t('已下发，主机下次上报（30 秒内）时执行'))
    dialog.value = false
    load()
  } finally {
    submitting.value = false
  }
}

async function approve(row) {
  try {
    await ElMessageBox.confirm(t('批准对 {p0} 执行「{p1}」？原因：{p2}', { p0: row.agent_id, p1: typeLabels[row.type], p2: row.reason }), t('批准处置'), { type: 'warning' })
  } catch {
    return
  }
  await api.approveAction(row.id)
  ElMessage.success(t('已批准'))
  load()
}

async function rollback(row) {
  let reason
  try {
    ;({ value: reason } = await ElMessageBox.prompt(t('撤销对 {p0} 的「{p1}」', { p0: row.agent_id, p1: typeLabels[row.type] }), t('撤销处置'), { inputPlaceholder: t('撤销原因') }))
  } catch {
    return
  }
  await api.rollbackAction(row.id, reason)
  ElMessage.success(t('撤销指令已下发'))
  load()
}

// 有进行中的处置时自动刷新
const timer = setInterval(() => {
  if (actions.value.some((a) => ['pending', 'sent'].includes(a.status))) load()
}, 5000)

onMounted(async () => {
  await load()
  // 从告警页跳转过来：按告警 IP 匹配主机
  if (route.query.ip && auth.isAdmin) {
    const agent = agents.value.find((a) => a.ips.includes(route.query.ip))
    openDialog({ agent_id: agent?.id || '', reason: route.query.reason || '' })
    if (!agent) ElMessage.warning(t('没有找到 IP 为 {p0} 的 Agent，请手动选择主机', { p0: route.query.ip }))
  }
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.sub { color: #909399; font-size: 12px; }
.hint { margin-left: 8px; color: #909399; font-size: 12px; }
</style>
