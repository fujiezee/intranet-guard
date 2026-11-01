<template>
  <div v-loading="loading">
    <div class="page-header"><h2>总览</h2></div>
    <el-row :gutter="16">
      <el-col :span="6"><el-card shadow="never"><el-statistic title="资产数量" :value="stats.assets" /></el-card></el-col>
      <el-col :span="6">
        <el-card shadow="never" class="clickable" @click="router.push('/incidents')">
          <el-statistic title="未结事件" :value="totalIncidents" />
          <div class="sev">
            <el-tag type="danger" size="small">高 {{ stats.open_incidents.high || 0 }}</el-tag>
            <el-tag type="warning" size="small">中 {{ stats.open_incidents.medium || 0 }}</el-tag>
            <span class="sub">开放端口 {{ stats.open_ports }}</span>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="clickable" @click="router.push('/vulns')">
          <el-statistic title="未修复漏洞" :value="totalVulns" />
          <div class="sev">
            <el-tag type="danger" size="small">高 {{ stats.open_vulns.high || 0 }}</el-tag>
            <el-tag type="warning" size="small">中 {{ stats.open_vulns.medium || 0 }}</el-tag>
            <el-tag type="info" size="small">低 {{ stats.open_vulns.low || 0 }}</el-tag>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="clickable" @click="router.push('/alerts')">
          <el-statistic title="未处理告警" :value="totalAlerts" />
          <div class="sev">
            <el-tag type="danger" size="small">高 {{ stats.open_alerts.high || 0 }}</el-tag>
            <el-tag type="warning" size="small">中 {{ stats.open_alerts.medium || 0 }}</el-tag>
            <el-tag type="info" size="small">低 {{ stats.open_alerts.low || 0 }}</el-tag>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="24">
        <el-card shadow="never" header="风险最高的资产">
          <el-table :data="risky" size="small" empty-text="暂无风险资产" @row-click="() => router.push('/assets')" row-class-name="clickable">
            <el-table-column label="风险" width="80">
              <template #default="{ row }"><el-tag size="small" effect="dark" :type="row.risk >= 60 ? 'danger' : row.risk >= 30 ? 'warning' : 'info'">{{ row.risk }}</el-tag></template>
            </el-table-column>
            <el-table-column label="资产" width="220"><template #default="{ row }"><span class="mono">{{ row.ip }}</span> {{ row.hostname }}</template></el-table-column>
            <el-table-column prop="owner" label="负责人" width="100" />
            <el-table-column label="原因"><template #default="{ row }"><span class="sub">{{ (row.risk_reasons || []).join('；') }}</span></template></el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :span="10">
        <el-card shadow="never" header="服务分布（Top 10）">
          <el-empty v-if="!stats.top_services.length" description="暂无数据" />
          <div v-for="s in stats.top_services" :key="s.service" class="bar-row">
            <span class="bar-label mono">{{ s.service }}</span>
            <el-progress :percentage="Math.round((s.count / maxService) * 100)" :format="() => s.count" :stroke-width="14" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="14">
        <el-card shadow="never" header="最新未处理告警">
          <el-table :data="recentAlerts" size="small" empty-text="暂无告警">
            <el-table-column label="级别" width="70">
              <template #default="{ row }"><SeverityTag :severity="row.severity" /></template>
            </el-table-column>
            <el-table-column prop="message" label="内容" />
            <el-table-column label="时间" width="170">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const router = useRouter()
const loading = ref(true)
const stats = ref({ assets: 0, open_ports: 0, running_tasks: 0, open_alerts: {}, open_vulns: {}, open_incidents: {}, top_services: [] })
const risky = ref([])
const totalIncidents = computed(() => Object.values(stats.value.open_incidents).reduce((a, b) => a + b, 0))
const recentAlerts = ref([])

const totalVulns = computed(() => Object.values(stats.value.open_vulns).reduce((a, b) => a + b, 0))
const totalAlerts = computed(() => Object.values(stats.value.open_alerts).reduce((a, b) => a + b, 0))
const maxService = computed(() => Math.max(1, ...stats.value.top_services.map((s) => s.count)))

onMounted(async () => {
  try {
    const [s, alerts, assets] = await Promise.all([api.stats(), api.alerts('open'), api.assets()])
    stats.value = s
    risky.value = assets.filter((a) => a.risk > 0).sort((a, b) => b.risk - a.risk).slice(0, 8)
    recentAlerts.value = alerts.slice(0, 8)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.sev { margin-top: 8px; display: flex; gap: 6px; }
.clickable { cursor: pointer; }
:deep(.clickable) { cursor: pointer; }
.sub { color: #909399; font-size: 12px; }
.bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
.bar-label { width: 110px; flex-shrink: 0; font-size: 13px; }
.bar-row .el-progress { flex: 1; }
</style>
