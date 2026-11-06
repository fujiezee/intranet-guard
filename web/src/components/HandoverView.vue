<template>
  <div>
    <div class="head">
      <b>{{ handover.author }}</b>
      <span class="sub">{{ formatTime(handover.from) }} – {{ formatTime(handover.to) }}</span>
    </div>
    <div class="line">
      {{ t('新告警 {p0}', { p0: totalOf(m.alerts) }) }}
      <SeverityCounts :counts="m.alerts" />
      <span class="sep">{{ t('新事件 {p0}，结案 {p1}', { p0: m.incidents, p1: m.resolved }) }}</span>
    </div>
    <div class="line">
      <span v-for="c in metricCards(m)" :key="c.title" class="metric">{{ c.title }} <b>{{ c.value }}</b></span>
    </div>
    <div class="line">
      {{ t('遗留待办 {p0} 项', { p0: s.open_total }) }}
      <span v-if="s.open_overdue" class="err">{{ t('，已超时 {p0} 项', { p0: s.open_overdue }) }}</span>
    </div>
    <ul v-if="s.open?.length" class="items">
      <li v-for="it in s.open" :key="`${it.kind}-${it.id}`">
        <SeverityTag :severity="it.severity" />
        {{ itemTitle(it) }}<span v-if="it.assignee" class="sub">（{{ it.assignee }}）</span>
      </li>
      <li v-if="s.open_total > s.open.length" class="sub">{{ t('…另有 {p0} 项', { p0: s.open_total - s.open.length }) }}</li>
    </ul>
    <div v-if="handover.note" class="note">{{ handover.note }}</div>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed } from 'vue'
import { formatTime } from '../format'
import { itemTitle, metricCards, totalOf } from '../duty'
import SeverityTag from './SeverityTag.vue'
import SeverityCounts from './SeverityCounts.vue'

const props = defineProps({ handover: Object })
const s = computed(() => props.handover.summary)
const m = computed(() => s.value.metrics)
</script>

<style scoped>
.head { display: flex; gap: 12px; align-items: baseline; margin-bottom: 8px; }
.line { margin: 6px 0; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.sep { margin-left: 12px; }
.metric { margin-right: 16px; }
.items { margin: 6px 0; padding-left: 0; list-style: none; }
.items li { margin: 4px 0; }
.note { white-space: pre-wrap; background: var(--el-fill-color-light); padding: 8px 12px; border-radius: 4px; margin-top: 8px; }
.sub { color: #909399; font-size: 12px; }
.err { color: var(--el-color-danger); }
</style>
