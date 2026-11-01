<template>
  <div>
    <div class="page-header">
      <h2>{{ t('告警') }}</h2>
      <div class="tools">
        <el-radio-group v-model="status" @change="load">
          <el-radio-button value="open">{{ t('未处理') }}</el-radio-button>
          <el-radio-button value="acked">{{ t('已处理') }}</el-radio-button>
          <el-radio-button value="">{{ t('全部') }}</el-radio-button>
        </el-radio-group>
        <el-button @click="load">{{ t('刷新') }}</el-button>
      </div>
    </div>
    <el-table :data="alerts" v-loading="loading" stripe>
      <el-table-column :label="t('级别')" width="70">
        <template #default="{ row }"><SeverityTag :severity="row.severity" /></template>
      </el-table-column>
      <el-table-column :label="t('类型')" width="110">
        <template #default="{ row }">{{ typeLabels[row.type] || row.type }}</template>
      </el-table-column>
      <el-table-column label="IP" width="140"><template #default="{ row }"><span class="mono">{{ row.ip }}</span></template></el-table-column>
      <el-table-column :label="t('内容')" min-width="260">
        <template #default="{ row }">
          {{ row.message }}
          <el-link v-if="row.incident_id" type="primary" :underline="false" class="inc" @click="router.push({ path: '/incidents', query: { id: row.incident_id } })">{{ t('事件 #{p0}', { p0: row.incident_id }) }}</el-link>
        </template>
      </el-table-column>
      <el-table-column :label="t('时间')" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column :label="t('处理')" width="210">
        <template #default="{ row }">
          <template v-if="row.status === 'acked'">
            <el-tooltip v-if="row.resolution === 'false_positive'" :content="row.resolution_note">
              <el-tag size="small" type="info">{{ t('误报') }}</el-tag>
            </el-tooltip>
            <el-tag v-else-if="row.resolution === 'simulation'" size="small" type="success">{{ t('自检') }}</el-tag>
            <span class="acked">{{ row.acked_by }}</span>
          </template>
          <template v-else-if="auth.isAdmin">
            <el-button size="small" @click="ack(row)">{{ t('确认') }}</el-button>
            <el-button size="small" link @click="falsePositive(row)">{{ t('误报') }}</el-button>
            <el-button size="small" link type="danger" @click="respond(row)">{{ t('处置') }}</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const router = useRouter()
const typeLabels = {
  new_asset: t('新主机'),
  new_port: t('新端口'),
  risky_port: t('高危端口'),
  ssh_bruteforce: t('暴力破解'),
  bruteforce_success: t('爆破成功'),
  root_login: t('root 登录'),
  file_changed: t('文件篡改'),
  suspicious_process: t('可疑进程'),
  agent_offline: t('Agent 离线'),
  ids: t('入侵检测'),
  vuln: t('漏洞'),
  honeypot: t('蜜罐'),
  suspicious_command: t('可疑命令'),
  webshell: 'Webshell',
  lateral_movement: t('横向移动'),
  agent_stopped: t('Agent 停止'),
  account_change: t('账户变更'),
  domain_attack: t('域攻击'),
  threat_intel: t('威胁情报'),
  dns_anomaly: t('DNS 异常'),
  c2_beacon: t('C2 心跳'),
  exfiltration: t('数据外传'),
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
    ;({ value: reason } = await ElMessageBox.prompt(t('请说明为什么是误报（例如：授权的漏洞扫描、运维变更）'), t('标记为误报'), {
      inputValidator: (v) => !!v?.trim() || t('请填写原因'),
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
.inc { margin-left: 6px; font-size: 12px; }
</style>
