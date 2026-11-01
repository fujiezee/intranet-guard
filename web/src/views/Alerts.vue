<template>
  <div>
    <div class="page-header">
      <h2>告警</h2>
      <div class="tools">
        <el-radio-group v-model="status" @change="load">
          <el-radio-button value="open">未处理</el-radio-button>
          <el-radio-button value="acked">已处理</el-radio-button>
          <el-radio-button value="">全部</el-radio-button>
        </el-radio-group>
        <el-button @click="load">刷新</el-button>
      </div>
    </div>
    <el-table :data="alerts" v-loading="loading" stripe>
      <el-table-column label="级别" width="70">
        <template #default="{ row }"><SeverityTag :severity="row.severity" /></template>
      </el-table-column>
      <el-table-column label="类型" width="110">
        <template #default="{ row }">{{ typeLabels[row.type] || row.type }}</template>
      </el-table-column>
      <el-table-column label="IP" width="140"><template #default="{ row }"><span class="mono">{{ row.ip }}</span></template></el-table-column>
      <el-table-column prop="message" label="内容" min-width="260" />
      <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column label="处理" width="210">
        <template #default="{ row }">
          <template v-if="row.status === 'acked'">
            <el-tooltip v-if="row.resolution === 'false_positive'" :content="row.resolution_note">
              <el-tag size="small" type="info">误报</el-tag>
            </el-tooltip>
            <el-tag v-else-if="row.resolution === 'simulation'" size="small" type="success">自检</el-tag>
            <span class="acked">{{ row.acked_by }}</span>
          </template>
          <template v-else-if="auth.isAdmin">
            <el-button size="small" @click="ack(row)">确认</el-button>
            <el-button size="small" link @click="falsePositive(row)">误报</el-button>
            <el-button size="small" link type="danger" @click="respond(row)">处置</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const router = useRouter()
const typeLabels = {
  new_asset: '新主机',
  new_port: '新端口',
  risky_port: '高危端口',
  ssh_bruteforce: 'SSH 爆破',
  bruteforce_success: '爆破成功',
  root_login: 'root 登录',
  file_changed: '文件篡改',
  suspicious_process: '可疑进程',
  agent_offline: 'Agent 离线',
  ids: '入侵检测',
  vuln: '漏洞',
  honeypot: '蜜罐',
  suspicious_command: '可疑命令',
  webshell: 'Webshell',
  lateral_movement: '横向移动',
  agent_stopped: 'Agent 停止',
}
const alerts = ref([])
const loading = ref(false)
const status = ref('open')

async function load() {
  loading.value = true
  try {
    alerts.value = await api.alerts(status.value)
  } finally {
    loading.value = false
  }
}

async function ack(row) {
  await api.ackAlert(row.id)
  load()
}

// 跳到处置页并带上告警信息，自动匹配告警主机上的 Agent
function respond(row) {
  router.push({ path: '/response', query: { ip: row.ip, reason: row.message.slice(0, 300) } })
}

// 标记误报：原因用于统计误报率、调优或抑制规则
async function falsePositive(row) {
  let reason
  try {
    ;({ value: reason } = await ElMessageBox.prompt('请说明为什么是误报（例如：授权的漏洞扫描、运维变更）', '标记为误报', {
      inputValidator: (v) => !!v?.trim() || '请填写原因',
    }))
  } catch {
    return
  }
  await api.ackAlert(row.id, { false_positive: true, reason })
  load()
}

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.acked { color: #909399; font-size: 12px; }
</style>
