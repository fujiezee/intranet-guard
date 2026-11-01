<template>
  <div>
    <div class="page-header">
      <h2>检测验证</h2>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-card shadow="never">
      <template #header>
        <div class="card-head">
          <span>攻击模拟自检</span>
          <span class="hint">在主机上执行无害的模拟动作，检查系统是否在规定时间内告警。自检产生的告警自动关闭，不会推送。</span>
        </div>
      </template>
      <div v-if="auth.isAdmin" class="run">
        <el-select v-model="agentID" placeholder="选择主机" filterable style="width: 200px">
          <el-option v-for="a in agents" :key="a.id" :label="`${a.id}${a.status === 'online' ? '' : '（离线）'}`" :value="a.id" />
        </el-select>
        <el-checkbox-group v-model="chosen">
          <el-tooltip v-for="s in scenarios" :key="s.id" :content="s.description">
            <el-checkbox :value="s.id">{{ s.name }}</el-checkbox>
          </el-tooltip>
        </el-checkbox-group>
        <el-button type="primary" :disabled="!agentID || !chosen.length" @click="run">开始自检</el-button>
      </div>
      <el-table :data="sims" size="small" stripe empty-text="还没有自检记录" style="margin-top: 12px">
        <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
        <el-table-column prop="agent_id" label="主机" width="140" />
        <el-table-column label="场景" width="150"><template #default="{ row }">{{ scenarioName(row.scenario) }}</template></el-table-column>
        <el-table-column label="结果" width="110">
          <template #default="{ row }"><el-tag size="small" :type="statusMap[row.status].type">{{ statusMap[row.status].label }}</el-tag></template>
        </el-table-column>
        <el-table-column label="检出耗时" width="100">
          <template #default="{ row }">{{ row.status === 'passed' ? (row.latency_ms / 1000).toFixed(1) + ' 秒' : '' }}</template>
        </el-table-column>
        <el-table-column label="说明" min-width="240"><template #default="{ row }"><span class="sub">{{ row.detail }}</span></template></el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="card-head">
          <span>检测规则（{{ rules.length }}）</span>
          <span class="hint">已有自检场景覆盖 {{ covered }} 条；没有自检的规则依赖真实事件或演练验证。</span>
        </div>
      </template>
      <el-table :data="rules" size="small" stripe>
        <el-table-column prop="name" label="规则" width="140" />
        <el-table-column prop="tactic" label="ATT&CK 战术" width="140" />
        <el-table-column label="技术编号" width="190">
          <template #default="{ row }">
            <template v-for="t in row.techniques" :key="t">
              <a v-if="/^T\d/.test(t)" class="tech mono" :href="attackURL(t)" target="_blank" rel="noopener">{{ t }}</a>
              <span v-else class="sub">{{ t }}</span>
            </template>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="级别" width="80" />
        <el-table-column prop="source" label="数据来源" width="160" />
        <el-table-column label="触发条件 / 处置建议" min-width="320">
          <template #default="{ row }">
            <div>{{ row.description }}</div>
            <div class="sub">处置：{{ row.response }}</div>
          </template>
        </el-table-column>
        <el-table-column label="自检" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.simulation" size="small" type="success">{{ scenarioName(row.simulation) }}</el-tag>
            <span v-else class="sub">-</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const statusMap = {
  pending: { label: '等待领取', type: 'info' },
  running: { label: '检测中', type: 'warning' },
  passed: { label: '通过', type: 'success' },
  failed: { label: '未检出', type: 'danger' },
  not_applicable: { label: '不适用', type: 'info' },
  error: { label: '执行出错', type: 'danger' },
}

const rules = ref([])
const scenarios = ref([])
const sims = ref([])
const agents = ref([])
const agentID = ref('')
const chosen = ref([])

const covered = computed(() => rules.value.filter((r) => r.simulation).length)
const scenarioName = (id) => scenarios.value.find((s) => s.id === id)?.name || id
// T1110.001 → https://attack.mitre.org/techniques/T1110/001/
const attackURL = (t) => `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`

async function load() {
  const [r, s, a] = await Promise.all([api.rules(), api.simulations(), api.agents()])
  rules.value = r.rules
  scenarios.value = r.scenarios
  sims.value = s
  agents.value = a
  if (!chosen.value.length) chosen.value = r.scenarios.map((x) => x.id)
}

async function run() {
  await api.createSimulations(agentID.value, chosen.value)
  ElMessage.success('已下发，主机下次上报（30 秒内）时开始执行，结果约 2 分钟内出来')
  load()
}

// 有进行中的自检时自动刷新
const timer = setInterval(() => {
  if (sims.value.some((s) => s.status === 'pending' || s.status === 'running')) {
    api.simulations().then((s) => (sims.value = s)).catch(() => {})
  }
}, 5000)

onMounted(load)
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.card-head { display: flex; align-items: baseline; gap: 12px; }
.hint, .sub { color: #909399; font-size: 12px; }
.run { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.tech { margin-right: 6px; color: #409eff; text-decoration: none; font-size: 12px; }
</style>
