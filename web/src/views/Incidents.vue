<template>
  <div>
    <div class="page-header">
      <h2>事件</h2>
      <div class="tools">
        <el-radio-group v-model="status" @change="load">
          <el-radio-button value="open">待处理</el-radio-button>
          <el-radio-button value="investigating">调查中</el-radio-button>
          <el-radio-button value="resolved">已解决</el-radio-button>
          <el-radio-button value="">全部</el-radio-button>
        </el-radio-group>
        <el-button @click="load">刷新</el-button>
      </div>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px"
      title="同一主机 2 小时内的入侵类告警自动归为一个事件；涉及 3 个及以上攻击阶段时升级为高危。资产变化、漏洞等告警不形成事件。" />

    <el-table :data="incidents" v-loading="loading" stripe empty-text="没有事件" @row-click="open" row-class-name="clickable">
      <el-table-column label="级别" width="70"><template #default="{ row }"><SeverityTag :severity="row.severity" /></template></el-table-column>
      <el-table-column label="#" width="60"><template #default="{ row }">{{ row.id }}</template></el-table-column>
      <el-table-column prop="title" label="事件" min-width="200" />
      <el-table-column label="攻击阶段" min-width="320">
        <template #default="{ row }"><StageBar :stages="row.stages" /></template>
      </el-table-column>
      <el-table-column prop="alert_count" label="告警数" width="80" />
      <el-table-column label="状态" width="90">
        <template #default="{ row }"><el-tag size="small" :type="statusMap[row.status].type">{{ statusMap[row.status].label }}</el-tag></template>
      </el-table-column>
      <el-table-column prop="assignee" label="负责人" width="100" />
      <el-table-column label="最近活动" width="170"><template #default="{ row }">{{ formatTime(row.last_seen) }}</template></el-table-column>
    </el-table>

    <el-drawer :model-value="!!detail" @close="close" size="760px" :title="detail ? `#${detail.incident.id} ${detail.incident.title}` : ''">
      <template v-if="detail">
        <div class="head">
          <SeverityTag :severity="detail.incident.severity" />
          <el-tag size="small" :type="statusMap[detail.incident.status].type">{{ statusMap[detail.incident.status].label }}</el-tag>
          <span class="sub">{{ formatTime(detail.incident.first_seen) }} — {{ formatTime(detail.incident.last_seen) }}，{{ detail.incident.alert_count }} 条告警</span>
        </div>
        <StageBar :stages="detail.incident.stages" style="margin: 12px 0" />

        <div v-if="auth.isAdmin" class="ops">
          <el-select :model-value="detail.incident.status" style="width: 130px" @change="(v) => update({ status: v })">
            <el-option v-for="(v, k) in statusMap" :key="k" :label="v.label" :value="k" />
          </el-select>
          <el-input v-model="assignee" placeholder="负责人" style="width: 140px" @change="update({ assignee })" />
          <el-button type="danger" plain @click="router.push({ path: '/response', query: { ip: detail.incident.ip, reason: `事件 #${detail.incident.id}：${detail.incident.title}` } })">处置主机</el-button>
          <span v-if="detail.agents.length === 0" class="sub">该地址没有 Agent，只有网络侧告警</span>
        </div>

        <h4>时间线</h4>
        <el-checkbox v-model="showAudit" style="margin-bottom: 8px">显示主机审计记录（登录、命令等，事件前后 30 分钟）</el-checkbox>
        <el-timeline>
          <el-timeline-item v-for="item in timeline" :key="item.key" :timestamp="formatTime(item.time)" :type="item.type" placement="top">
            <div v-if="item.alert">
              <el-tag size="small" effect="plain">{{ stageName(item.alert.type) }}</el-tag>
              <SeverityTag :severity="item.alert.severity" />
              <span class="msg">{{ item.alert.message }}</span>
            </div>
            <div v-else class="audit">
              <el-tag size="small" type="info">{{ eventLabels[item.event.type] || item.event.type }}</el-tag>
              <span class="mono">{{ [item.event.user, item.event.src_ip].filter(Boolean).join(' @ ') }}</span>
              {{ item.event.path }} {{ item.event.detail }}
            </div>
          </el-timeline-item>
        </el-timeline>

        <h4>处置记录</h4>
        <div v-for="n in detail.notes" :key="n.id" class="note">
          <div class="sub">{{ n.author }} · {{ formatTime(n.created_at) }}</div>
          <div>{{ n.body }}</div>
        </div>
        <div v-if="auth.isAdmin" class="note-input">
          <el-input v-model="note" type="textarea" :rows="2" placeholder="记录排查结论、已采取的措施……" />
          <el-button :disabled="!note.trim()" @click="addNote">添加</el-button>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'
import StageBar from '../components/StageBar.vue'

const statusMap = {
  open: { label: '待处理', type: 'danger' },
  investigating: { label: '调查中', type: 'warning' },
  resolved: { label: '已解决', type: 'success' },
  false_positive: { label: '误报', type: 'info' },
}
// 告警类型 → 阶段名（与后端 alert/stages.go 一致）
const alertStage = {
  ids: '网络攻击', honeypot: '侦察探测', ssh_bruteforce: '凭据获取', bruteforce_success: '初始访问', root_login: '初始访问',
  suspicious_command: '执行', suspicious_process: '执行', file_changed: '持久化', webshell: '持久化',
  agent_stopped: '防御规避', agent_offline: '防御规避', lateral_movement: '横向移动',
}
const eventLabels = { login_success: '登录成功', login_failed: '登录失败', sudo: 'sudo', command: '命令', suspicious_command: '可疑命令',
  file_changed: '文件变更', webshell: 'Webshell', suspicious_process: '可疑进程' }
const stageName = (t) => alertStage[t] || t

const route = useRoute()
const router = useRouter()
const status = ref('open')
const incidents = ref([])
const loading = ref(false)
const detail = ref(null)
const assignee = ref('')
const note = ref('')
const showAudit = ref(true)

const timeline = computed(() => {
  if (!detail.value) return []
  const items = detail.value.alerts.map((a) => ({
    key: 'a' + a.id, time: a.created_at, alert: a, type: a.severity === 'high' ? 'danger' : a.severity === 'medium' ? 'warning' : 'info',
  }))
  if (showAudit.value) {
    detail.value.events
      .filter((e) => e.type !== 'login_failed') // 爆破期间的大量失败登录已体现在告警中
      .forEach((e, i) => items.push({ key: 'e' + i, time: e.time, event: e, type: '' }))
  }
  return items.sort((x, y) => new Date(x.time) - new Date(y.time))
})

async function load() {
  loading.value = true
  try {
    incidents.value = await api.incidents(status.value)
  } finally {
    loading.value = false
  }
}

async function open(row) {
  detail.value = await api.incident(row.id)
  assignee.value = detail.value.incident.assignee || ''
  note.value = ''
}

function close() {
  detail.value = null
  if (route.query.id) router.replace({ query: {} })
}

async function update(body) {
  await api.updateIncident(detail.value.incident.id, body)
  await open(detail.value.incident)
  load()
}

async function addNote() {
  await api.addIncidentNote(detail.value.incident.id, note.value)
  await open(detail.value.incident)
}

onMounted(async () => {
  await load()
  if (route.query.id) open({ id: route.query.id })
})
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
:deep(.clickable) { cursor: pointer; }
.head { display: flex; align-items: center; gap: 8px; }
.ops { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
.sub { color: #909399; font-size: 12px; }
.msg { margin-left: 6px; }
.audit { color: #606266; font-size: 13px; }
.note { border-left: 3px solid #dcdfe6; padding: 4px 10px; margin-bottom: 8px; }
.note-input { display: flex; gap: 8px; align-items: flex-start; }
h4 { margin: 20px 0 8px; }
</style>
