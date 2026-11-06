<template>
  <div>
    <div class="page-header">
      <h2>{{ t('报表') }}</h2>
      <el-radio-group v-model="kind" @change="load">
        <el-radio-button value="">{{ t('全部') }}</el-radio-button>
        <el-radio-button value="daily">{{ t('日报') }}</el-radio-button>
        <el-radio-button value="weekly">{{ t('周报') }}</el-radio-button>
      </el-radio-group>
    </div>

    <el-table :data="reports" v-loading="loading" stripe :empty-text="t('暂无报表。每天 9:00 生成前一天的日报，每周一 9:00 生成上周的周报。')"
      row-class-name="clickable" @row-click="open">
      <el-table-column prop="title" :label="t('报表')" min-width="200" />
      <el-table-column :label="t('生成时间')" width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
    </el-table>

    <el-drawer :model-value="!!detail" size="720px" :title="detail?.title" @close="detail = null">
      <template v-if="detail">
        <div class="actions">
          <span class="sub">{{ formatTime(detail.period_start) }} – {{ formatTime(detail.period_end) }}</span>
          <el-button size="small" @click="exportMarkdown">{{ t('导出 Markdown') }}</el-button>
        </div>

        <h4>{{ t('值守') }}</h4>
        <div class="line">{{ t('新告警 {p0}', { p0: totalOf(d.metrics.alerts) }) }} <SeverityCounts :counts="d.metrics.alerts" /></div>
        <div class="line">{{ t('新事件 {p0}，结案 {p1}', { p0: d.metrics.incidents, p1: d.metrics.resolved }) }}</div>
        <el-row :gutter="12" class="cards">
          <el-col v-for="c in metricCards(d.metrics)" :key="c.title" :span="8">
            <el-card shadow="never">
              <div class="stat-title">{{ c.title }}</div>
              <div class="stat-value">{{ c.value }}</div>
              <div class="sub">{{ c.sub }}</div>
            </el-card>
          </el-col>
        </el-row>

        <h4>{{ t('漏洞') }}</h4>
        <div class="line">{{ t('新发现') }} <SeverityCounts :counts="d.new_vulns" /></div>
        <div class="line">{{ t('已修复') }} <SeverityCounts :counts="d.fixed_vulns" /></div>

        <h4>{{ t('生成时未处理') }}</h4>
        <div class="line">{{ t('事件 {p0}，告警 {p1}，漏洞 {p2}', { p0: totalOf(d.open_incidents), p1: totalOf(d.open_alerts), p2: totalOf(d.open_vulns) }) }}</div>

        <h4>{{ t('风险最高的资产') }}</h4>
        <el-table :data="d.top_assets" size="small" :empty-text="t('暂无风险资产')">
          <el-table-column :label="t('风险')" width="70"><template #default="{ row }">{{ row.risk }}</template></el-table-column>
          <el-table-column :label="t('资产')" width="220"><template #default="{ row }"><span class="mono">{{ row.ip }}</span> {{ row.name }}</template></el-table-column>
          <el-table-column prop="owner" :label="t('负责人')" width="100" />
          <el-table-column :label="t('原因')"><template #default="{ row }"><span class="sub">{{ (row.reasons || []).join('；') }}</span></template></el-table-column>
        </el-table>

        <h4>{{ t('离线节点') }}</h4>
        <div v-if="!d.offline_agents.length && !d.offline_probes.length" class="sub">{{ t('无') }}</div>
        <div v-if="d.offline_agents.length" class="line">
          {{ t('Agent {p0} 台：', { p0: d.offline_agents.length }) }}{{ d.offline_agents.map((a) => a.hostname || a.id).join('、') }}
        </div>
        <div v-if="d.offline_probes.length" class="line">{{ t('探针 {p0} 个：', { p0: d.offline_probes.length }) }}{{ d.offline_probes.join('、') }}</div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import { metricCards, totalOf } from '../duty'
import SeverityCounts from '../components/SeverityCounts.vue'

const kind = ref('')
const loading = ref(true)
const reports = ref([])
const detail = ref(null)
const d = computed(() => detail.value?.data)

async function load() {
  loading.value = true
  try {
    reports.value = await api.reports(kind.value)
  } finally {
    loading.value = false
  }
}

async function open(row) {
  detail.value = await api.report(row.id)
}

// 导出与推送到群里的内容相同的 Markdown 文本
function exportMarkdown() {
  const blob = new Blob([detail.value.text + '\n'], { type: 'text/markdown;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${detail.value.title}.md`
  a.click()
  URL.revokeObjectURL(a.href)
}

onMounted(load)
</script>

<style scoped>
.actions { display: flex; justify-content: space-between; align-items: center; }
h4 { margin: 20px 0 8px; }
.line { margin: 6px 0; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.cards { margin-top: 8px; row-gap: 12px; }
.stat-title { font-size: 12px; color: var(--el-text-color-regular); }
.stat-value { font-size: 18px; margin: 2px 0; }
.sub { color: #909399; font-size: 12px; }
:deep(.clickable) { cursor: pointer; }
</style>
