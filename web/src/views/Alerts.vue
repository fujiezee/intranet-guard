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
      <el-table-column label="处理" width="150">
        <template #default="{ row }">
          <span v-if="row.status === 'acked'" class="acked">{{ row.acked_by }} 已确认</span>
          <el-button v-else-if="auth.isAdmin" size="small" @click="ack(row)">确认</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

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

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.acked { color: #909399; font-size: 12px; }
</style>
