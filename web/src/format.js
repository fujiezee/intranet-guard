export function formatTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
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
