<template>
  <div>
    <div class="page-header">
      <h2>主机审计</h2>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-card shadow="never" :header="`Agent（${agents.length}，在线 ${onlineCount}）`">
      <el-empty v-if="!agents.length" description="还没有 Agent 接入，部署方法见 README" :image-size="60" />
      <el-table v-else :data="agents" size="small" @row-click="(row) => selectAgent(row.id)" row-class-name="clickable">
        <el-table-column label="状态" width="80">
          <template #default="{ row }">
            <el-tag size="small" :type="statusMap[row.status]?.type">{{ statusMap[row.status]?.label || row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="id" label="Agent ID" min-width="140" />
        <el-table-column label="IP" min-width="160">
          <template #default="{ row }"><span class="mono">{{ row.ips.join(', ') }}</span></template>
        </el-table-column>
        <el-table-column prop="os" label="系统" width="120" />
        <el-table-column prop="version" label="版本" width="80" />
        <el-table-column label="采集能力" min-width="220">
          <template #default="{ row }">
            <el-tag v-for="c in row.capabilities || []" :key="c" size="small" type="info" class="cap">{{ capLabels[c] || c }}</el-tag>
            <el-tooltip v-if="(row.os?.startsWith('linux') || row.os?.startsWith('windows')) && !(row.capabilities || []).includes('exec_monitor')"
              :content="row.os?.startsWith('windows') ? '尚未收到进程创建事件（4688）：确认已开启“审核进程创建”，域组策略未将其关闭' : '命令审计未启用：Agent 需要在 Linux 上以 root 运行'">
              <el-tag size="small" type="warning" class="cap">无命令审计</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="最后心跳" width="170"><template #default="{ row }">{{ formatTime(row.last_seen) }}</template></el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="filters">
          <span>审计日志</span>
          <el-select v-model="filter.agent_id" placeholder="全部主机" clearable style="width: 160px" @change="loadEvents">
            <el-option v-for="a in agents" :key="a.id" :label="a.id" :value="a.id" />
          </el-select>
          <el-select v-model="filter.type" placeholder="全部类型" clearable style="width: 140px" @change="loadEvents">
            <el-option v-for="(label, value) in eventLabels" :key="value" :label="label" :value="value" />
          </el-select>
          <el-input v-model="filter.src_ip" placeholder="来源 IP" clearable style="width: 160px" @change="loadEvents" />
        </div>
      </template>
      <el-table :data="events" v-loading="loadingEvents" size="small" stripe empty-text="暂无事件">
        <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.time) }}</template></el-table-column>
        <el-table-column prop="agent_id" label="主机" width="130" />
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="eventTagType[row.type]">{{ eventLabels[row.type] || row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="user" label="用户" width="110" />
        <el-table-column label="来源 IP" width="140"><template #default="{ row }"><span class="mono">{{ row.src_ip }}</span></template></el-table-column>
        <el-table-column label="详情" min-width="300">
          <template #default="{ row }"><span class="mono">{{ [row.path, row.detail].filter(Boolean).join('  ') }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'

const eventLabels = {
  login_success: '登录成功',
  login_failed: '登录失败',
  sudo: 'sudo',
  command: '命令',
  suspicious_command: '可疑命令',
  file_changed: '文件变更',
  webshell: 'Webshell',
  suspicious_process: '可疑进程',
  account_change: '账户变更',
  domain_attack: '域攻击',
}
const eventTagType = {
  login_success: 'success',
  login_failed: 'warning',
  sudo: 'info',
  command: 'info',
  suspicious_command: 'danger',
  file_changed: 'danger',
  webshell: 'danger',
  suspicious_process: 'danger',
  account_change: 'warning',
  domain_attack: 'danger',
}
const statusMap = {
  online: { label: '在线', type: 'success' },
  offline: { label: '离线', type: 'danger' },
  stopped: { label: '已停止', type: 'warning' },
}
const capLabels = { auth_log: '登录审计', fim: '文件完整性', webshell: 'Webshell', process_scan: '进程扫描', exec_monitor: '命令审计',
  winlog: 'Windows 事件日志' }

const agents = ref([])
const events = ref([])
const loadingEvents = ref(false)
const filter = reactive({ agent_id: '', type: '', src_ip: '' })
const onlineCount = computed(() => agents.value.filter((a) => a.status === 'online').length)

async function loadEvents() {
  loadingEvents.value = true
  try {
    const params = Object.fromEntries(Object.entries(filter).filter(([, v]) => v))
    events.value = await api.hostEvents(params)
  } finally {
    loadingEvents.value = false
  }
}

function selectAgent(id) {
  filter.agent_id = id
  loadEvents()
}

async function load() {
  agents.value = await api.agents()
  loadEvents()
}

onMounted(load)
</script>

<style scoped>
.filters { display: flex; align-items: center; gap: 8px; }
.cap { margin: 2px 4px 2px 0; }
.filters > span { margin-right: 8px; font-weight: 500; }
:deep(.clickable) { cursor: pointer; }
</style>
