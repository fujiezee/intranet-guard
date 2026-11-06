import { t } from './i18n'

export function formatTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// 时长（秒）写成"8 分钟""1.5 小时""2.3 天"，与推送消息一致。
export function formatDuration(sec) {
  const n = Math.abs(sec)
  const one = (v) => String(Math.round(v * 10) / 10)
  if (n < 60) return t('{p0} 秒', { p0: Math.round(n) })
  if (n < 3600) return t('{p0} 分钟', { p0: Math.floor(n / 60) })
  if (n < 48 * 3600) return t('{p0} 小时', { p0: one(n / 3600) })
  return t('{p0} 天', { p0: one(n / 86400) })
}

// 资产显示名：手动名称 > Agent 上报的主机名 > 扫描得到的主机名。
export function assetName(a) {
  return a.name || a.agent_hostname || a.hostname || ''
}

// 按数值比较 IPv4 地址，用于表格排序。
export function compareIP(a, b) {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i]
  return 0
}
