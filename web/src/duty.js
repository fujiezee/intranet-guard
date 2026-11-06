import { t } from './i18n'
import { formatDuration } from './format'

function avg(sec, n) {
  return n ? formatDuration(sec) : '—'
}

export function percent(part, total) {
  return total ? `${Math.round((part * 100) / total)}%` : '—'
}

export function totalOf(m) {
  return Object.values(m || {}).reduce((a, b) => a + b, 0)
}

// 待办事项的标题：事件带编号，告警即告警内容。
export function itemTitle(it) {
  return it.kind === 'incident' ? t('事件 #{p0}：{p1}', { p0: it.id, p1: it.title }) : it.title
}

// 值守指标卡片：工作台、交接记录和报表共用。
export function metricCards(m) {
  return [
    { title: t('平均响应'), value: avg(m.mtta_seconds, m.mtta_samples), sub: t('{p0} 项已确认或认领', { p0: m.mtta_samples }) },
    { title: t('平均处置'), value: avg(m.mttr_seconds, m.mttr_samples), sub: t('{p0} 个事件已结案', { p0: m.mttr_samples }) },
    { title: t('SLA 达标率'), value: percent(m.sla_met, m.sla_total), sub: `${m.sla_met}/${m.sla_total}` },
    { title: t('误报率'), value: percent(m.false_positives, m.handled), sub: t('已处理 {p0} 条告警', { p0: m.handled }) },
    { title: t('平均发现'), value: avg(m.mttd_seconds, m.mttd_samples), sub: t('攻击模拟自检 {p0} 次', { p0: m.mttd_samples }) },
  ]
}
