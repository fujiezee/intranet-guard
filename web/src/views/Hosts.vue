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
            <el-tag size="small" :type="row.status === 'online' ? 'success' : 'danger'">{{ row.status === 'online' ? '在线' : '离线' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="id" label="Agent ID" min-width="140" />
        <el-table-column label="IP" min-width="160">
          <template #default="{ row }"><span class="mono">{{ row.ips.join(', ') }}</span></template>
        </el-table-column>
        <el-table-column prop="os" label="系统" width="120" />
        <el-table-column prop="version" label="版本" width="80" />
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
  file_changed: '文件变更',
  suspicious_process: '可疑进程',
}
const eventTagType = { login_success: 'success', login_failed: 'warning', sudo: 'info', file_changed: 'danger', suspicious_process: 'danger' }

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
.filters > span { margin-right: 8px; font-weight: 500; }
:deep(.clickable) { cursor: pointer; }
</style>
