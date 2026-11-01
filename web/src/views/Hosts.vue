<template>
  <div>
    <div class="page-header">
      <h2>{{ t('主机审计') }}</h2>
      <div>
        <el-button @click="upgradesOpen = true">{{ t('Agent 升级') }}</el-button>
        <el-button @click="load">{{ t('刷新') }}</el-button>
      </div>
    </div>

    <el-card shadow="never" :header="t('Agent（{p0}，在线 {p1}）', { p0: agents.length, p1: onlineCount })">
      <el-empty v-if="!agents.length" :description="t('还没有 Agent 接入，部署方法见 README')" :image-size="60" />
      <el-table v-else :data="agents" size="small" @row-click="(row) => selectAgent(row.id)" row-class-name="clickable">
        <el-table-column :label="t('状态')" width="80">
          <template #default="{ row }">
            <el-tag size="small" :type="statusMap[row.status]?.type">{{ statusMap[row.status]?.label || row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="id" label="Agent ID" min-width="140" />
        <el-table-column label="IP" min-width="160">
          <template #default="{ row }"><span class="mono">{{ row.ips.join(', ') }}</span></template>
        </el-table-column>
        <el-table-column prop="os" :label="t('系统')" width="120" />
        <el-table-column prop="version" :label="t('版本')" width="80" />
        <el-table-column :label="t('采集能力')" min-width="220">
          <template #default="{ row }">
            <el-tag v-for="c in row.capabilities || []" :key="c" size="small" type="info" class="cap">{{ capLabels[c] || c }}</el-tag>
            <el-tooltip v-if="(row.os?.startsWith('linux') || row.os?.startsWith('windows')) && !(row.capabilities || []).includes('exec_monitor')"
              :content="row.os?.startsWith('windows') ? t('尚未收到进程创建事件（4688）：确认已开启“审核进程创建”，域组策略未将其关闭') : t('命令审计未启用：Agent 需要在 Linux 上以 root 运行')">
              <el-tag size="small" type="warning" class="cap">{{ t('无命令审计') }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column :label="t('最后心跳')" width="170"><template #default="{ row }">{{ formatTime(row.last_seen) }}</template></el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="filters">
          <span>{{ t('审计日志') }}</span>
          <el-select v-model="filter.agent_id" :placeholder="t('全部主机')" clearable style="width: 160px" @change="loadEvents">
            <el-option v-for="a in agents" :key="a.id" :label="a.id" :value="a.id" />
          </el-select>
          <el-select v-model="filter.type" :placeholder="t('全部类型')" clearable style="width: 140px" @change="loadEvents">
            <el-option v-for="(label, value) in eventLabels" :key="value" :label="label" :value="value" />
          </el-select>
          <el-input v-model="filter.src_ip" :placeholder="t('来源 IP')" clearable style="width: 160px" @change="loadEvents" />
        </div>
      </template>
      <el-table :data="events" v-loading="loadingEvents" size="small" stripe :empty-text="t('暂无事件')">
        <el-table-column :label="t('时间')" width="170"><template #default="{ row }">{{ formatTime(row.time) }}</template></el-table-column>
        <el-table-column prop="agent_id" :label="t('主机')" width="130" />
        <el-table-column :label="t('类型')" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="eventTagType[row.type]">{{ eventLabels[row.type] || row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="user" :label="t('用户')" width="110" />
        <el-table-column :label="t('来源 IP')" width="140"><template #default="{ row }"><span class="mono">{{ row.src_ip }}</span></template></el-table-column>
        <el-table-column :label="t('详情')" min-width="300">
          <template #default="{ row }"><span class="mono">{{ [row.path, row.detail].filter(Boolean).join('  ') }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>
    <AgentUpgrades v-model="upgradesOpen" @update:model-value="(v) => !v && load()" />
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import AgentUpgrades from '../components/AgentUpgrades.vue'

const eventLabels = {
  login_success: t('登录成功'),
  login_failed: t('登录失败'),
  sudo: 'sudo',
  command: t('命令'),
  suspicious_command: t('可疑命令'),
  file_changed: t('文件变更'),
  webshell: 'Webshell',
  suspicious_process: t('可疑进程'),
  account_change: t('账户变更'),
  domain_attack: t('域攻击'),
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
  online: { label: t('在线'), type: 'success' },
  offline: { label: t('离线'), type: 'danger' },
  stopped: { label: t('已停止'), type: 'warning' },
}
const capLabels = { auth_log: t('登录审计'), fim: t('文件完整性'), webshell: 'Webshell', process_scan: t('进程扫描'), exec_monitor: t('命令审计'),
  winlog: t('Windows 事件日志') }

const upgradesOpen = ref(false)
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
