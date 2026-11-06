<template>
  <div>
    <div class="page-header">
      <h2>{{ t('值守工作台') }}</h2>
      <div class="tools">
        <el-radio-group v-model="range" @change="loadMetrics">
          <el-radio-button value="today">{{ t('今日') }}</el-radio-button>
          <el-radio-button value="7d">{{ t('近 7 天') }}</el-radio-button>
          <el-radio-button value="30d">{{ t('近 30 天') }}</el-radio-button>
        </el-radio-group>
        <el-button v-if="auth.isAdmin" @click="openSLA">{{ t('SLA 设置') }}</el-button>
        <el-button v-if="auth.isAdmin" type="primary" @click="openHandover">{{ t('交接班') }}</el-button>
      </div>
    </div>

    <el-row :gutter="16">
      <el-col :span="4">
        <el-card shadow="never">
          <div class="stat-title">{{ t('待办') }}</div>
          <div class="stat-value">{{ queue.length }}</div>
          <div class="sub" :class="{ err: overdueCount }">{{ t('已超时 {p0}', { p0: overdueCount }) }}</div>
        </el-card>
      </el-col>
      <el-col v-for="c in cards" :key="c.title" :span="4">
        <el-card shadow="never">
          <div class="stat-title">{{ c.title }}</div>
          <div class="stat-value">{{ c.value }}</div>
          <div class="sub">{{ c.sub }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="card-header">
          <span>{{ t('待办队列') }}</span>
          <span class="sub">{{ t('每 30 秒刷新') }}</span>
        </div>
      </template>
      <el-table :data="queue" v-loading="loading" size="small" :empty-text="t('没有待处理的事件和告警')" :row-class-name="rowClass">
        <el-table-column :label="t('级别')" width="70"><template #default="{ row }"><SeverityTag :severity="row.severity" /></template></el-table-column>
        <el-table-column :label="t('内容')" min-width="320">
          <template #default="{ row }">
            <a class="link" @click="openItem(row)">{{ itemTitle(row) }}</a>
            <span v-if="row.alert_count" class="sub">{{ t('（{p0} 条告警）', { p0: row.alert_count }) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('负责人')" width="100"><template #default="{ row }">{{ row.assignee || '—' }}</template></el-table-column>
        <el-table-column :label="t('已等待')" width="100"><template #default="{ row }">{{ formatDuration((now - new Date(row.created_at)) / 1000) }}</template></el-table-column>
        <el-table-column :label="t('SLA')" width="170">
          <template #default="{ row }"><span :class="clock(row).cls">{{ clock(row).text }}</span></template>
        </el-table-column>
        <el-table-column v-if="auth.isAdmin" :label="t('操作')" width="120">
          <template #default="{ row }">
            <el-button v-if="row.kind === 'incident' && !row.assignee" size="small" link type="primary" @click="claim(row)">{{ t('认领') }}</el-button>
            <el-button v-else-if="row.kind === 'alert'" size="small" link type="primary" @click="ack(row)">{{ t('确认') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="card-header">
          <span>{{ t('上一班交接') }}</span>
          <el-button size="small" link type="primary" :disabled="!handovers.length" @click="historyOpen = true">{{ t('交接记录') }}</el-button>
        </div>
      </template>
      <el-empty v-if="!handovers.length" :image-size="60" :description="t('还没有交接记录')" />
      <HandoverView v-else :handover="handovers[0]" />
    </el-card>

    <el-dialog v-model="handoverOpen" :title="t('交接班')" width="720px">
      <HandoverView v-if="preview" :handover="preview" />
      <el-input v-model="note" type="textarea" :rows="4" maxlength="2000" show-word-limit style="margin-top: 12px"
        :placeholder="t('交接备注：正在跟进的事项、需要下一班注意的情况')" />
      <template #footer>
        <span class="sub footer-hint">{{ t('保存后推送到已启用的推送渠道') }}</span>
        <el-button @click="handoverOpen = false">{{ t('取消') }}</el-button>
        <el-button type="primary" :loading="saving" @click="submitHandover">{{ t('交接') }}</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="historyOpen" :title="t('交接记录')" size="720px">
      <div v-for="h in handovers" :key="h.id" class="history-item"><HandoverView :handover="h" /></div>
    </el-drawer>

    <el-dialog v-model="slaOpen" :title="t('SLA 设置')" width="520px">
      <el-table :data="slaRows" size="small">
        <el-table-column :label="t('级别')" width="80"><template #default="{ row }"><SeverityTag :severity="row.sev" /></template></el-table-column>
        <el-table-column :label="t('响应时限（分钟）')">
          <template #default="{ row }"><el-input-number v-model="slaForm.response[row.sev]" :min="0" :max="43200" size="small" controls-position="right" /></template>
        </el-table-column>
        <el-table-column :label="t('结案时限（分钟）')">
          <template #default="{ row }"><el-input-number v-model="slaForm.resolve[row.sev]" :min="0" :max="43200" size="small" controls-position="right" /></template>
        </el-table-column>
      </el-table>
      <div class="sub" style="margin-top: 8px">{{ t('0 表示不计时。响应：产生到确认或认领；结案：事件产生到结案。') }}</div>
      <template #footer>
        <el-button @click="slaOpen = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="saveSLA">{{ t('保存') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatDuration } from '../format'
import SeverityTag from '../components/SeverityTag.vue'
import HandoverView from '../components/HandoverView.vue'
import { itemTitle, metricCards } from '../duty'

const router = useRouter()
const loading = ref(true)
const range = ref('today')
const queue = ref([])
const metrics = ref(null)
const handovers = ref([])
const now = ref(Date.now())

const cards = computed(() => (metrics.value ? metricCards(metrics.value) : []))

// clock 显示最紧迫的时限：未认领时看响应时限，已认领的事件看结案时限。
function clock(row) {
  const due = !row.acked_at && row.response_due ? row.response_due : row.resolve_due
  if (!due) return { text: row.acked_at ? t('已认领') : t('不计时'), cls: 'sub' }
  const left = (new Date(due) - now.value) / 1000
  const label = !row.acked_at && row.response_due ? t('响应') : t('结案')
  if (left < 0) return { text: t('{p0}已超时 {p1}', { p0: label, p1: formatDuration(-left) }), cls: 'err' }
  return { text: t('{p0}剩 {p1}', { p0: label, p1: formatDuration(left) }), cls: left < 0.25 * slaSpan(row, due) ? 'warn' : '' }
}

function slaSpan(row, due) {
  return (new Date(due) - new Date(row.created_at)) / 1000
}

const overdueCount = computed(() => queue.value.filter((r) => clock(r).cls === 'err').length)

function rowClass({ row }) {
  return clock(row).cls === 'err' ? 'overdue' : ''
}

async function loadQueue() {
  now.value = Date.now()
  queue.value = await api.dutyQueue()
}

async function loadMetrics() {
  metrics.value = await api.dutyMetrics(range.value)
}

async function load() {
  try {
    await Promise.all([loadQueue(), loadMetrics(), api.handovers().then((h) => (handovers.value = h))])
  } finally {
    loading.value = false
  }
}

function openItem(row) {
  if (row.kind === 'incident') router.push({ path: '/incidents', query: { id: row.id } })
  else router.push('/alerts')
}

async function claim(row) {
  await api.updateIncident(row.id, { assignee: auth.user.username, status: 'investigating' })
  ElMessage.success(t('已认领'))
  loadQueue()
  loadMetrics()
}

async function ack(row) {
  try {
    await ElMessageBox.confirm(row.title, t('确认告警'), { type: 'info' })
  } catch {
    return
  }
  await api.ackAlert(row.id)
  loadQueue()
  loadMetrics()
}

// 交接班
const handoverOpen = ref(false)
const historyOpen = ref(false)
const preview = ref(null)
const note = ref('')
const saving = ref(false)

async function openHandover() {
  note.value = ''
  preview.value = await api.previewHandover()
  handoverOpen.value = true
}

async function submitHandover() {
  saving.value = true
  try {
    await api.createHandover(note.value)
    ElMessage.success(t('已交接'))
    handoverOpen.value = false
    handovers.value = await api.handovers()
  } finally {
    saving.value = false
  }
}

// SLA 设置
const slaOpen = ref(false)
const slaRows = [{ sev: 'high' }, { sev: 'medium' }, { sev: 'low' }]
const slaForm = reactive({ response: {}, resolve: {} })

async function openSLA() {
  const s = await api.sla()
  for (const k of ['response', 'resolve']) {
    slaForm[k] = Object.fromEntries(slaRows.map(({ sev }) => [sev, s[k]?.[sev] || 0]))
  }
  slaOpen.value = true
}

async function saveSLA() {
  await api.setSLA({ response: { ...slaForm.response }, resolve: { ...slaForm.resolve } })
  ElMessage.success(t('已保存'))
  slaOpen.value = false
  loadQueue()
  loadMetrics()
}

let timer
onMounted(() => {
  load()
  timer = setInterval(() => {
    loadQueue()
    loadMetrics()
  }, 30000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.tools { display: flex; gap: 8px; align-items: center; }
.el-col > .el-card { height: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.stat-title { font-size: 12px; color: var(--el-text-color-regular); line-height: 20px; }
.stat-value { font-size: 20px; margin: 2px 0; }
.sub { color: #909399; font-size: 12px; }
.err { color: var(--el-color-danger); }
.warn { color: var(--el-color-warning); }
.link { cursor: pointer; color: var(--el-color-primary); }
:deep(.overdue) { background: var(--el-color-danger-light-9); }
.footer-hint { margin-right: 12px; }
.history-item { padding-bottom: 16px; margin-bottom: 16px; border-bottom: 1px solid var(--el-border-color-lighter); }
</style>
