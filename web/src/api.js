import { ElMessage } from 'element-plus'
import { lang, t } from './i18n'
import { auth, clearSession } from './auth'
import router from './router'

const messages = {
  'unauthorized': '登录已失效，请重新登录',
  'forbidden': '没有权限执行该操作',
  'invalid username or password': '用户名或密码错误',
  'too many failed attempts, try again later': '失败次数过多，请 5 分钟后再试',
  'old password is incorrect': '原密码错误',
  'username already exists': '用户名已存在',
  'cannot delete yourself': '不能删除自己',
  'cannot remove the last admin': '不能删除最后一个管理员',
  'suppression already exists': '该抑制规则已存在',
  'reason is required when marking a false positive': '标记误报需要填写原因',
  'group name already exists': '资产组名称已存在',
  'no agent release available (deploy the management server from a release bundle)': '管理中心没有可分发的 Agent 版本（请用安装包部署管理中心）',
  'kind must be cluster or admin': '请选择资产组类型',
  '1-1000 members required': '请填写成员（1～1000 个 IP 或网段）',
  'name is required (at most 64 characters)': '请填写名称（最多 64 个字符）',
  'no valid IP, CIDR or domain found': '没有识别出有效的 IP、网段或域名',
  'url must be http or https': '订阅地址必须是 http 或 https',
  'work hours must satisfy 0 <= start < end <= 24; exfil_bytes >= 0': '工作时间需满足 0 ≤ 开始 < 结束 ≤ 24',
  'indicator not found (feed indicators are managed by their feed)': '订阅源的条目随订阅源管理，不能单独删除',
  'an action cannot be approved by the admin who created it': '不能批准自己发起的处置，需要另一位管理员',
  'reason is required (at most 500 characters)': '请填写处置原因',
  'only completed block / quarantine / isolate actions can be rolled back, once': '只有已完成的封禁、隔离文件、隔离主机可以撤销，且只能撤销一次',
  'scope already exists': '该授权范围已存在',
  'scope is too large (at most /8)': '授权范围过大（最大 /8）',
  'cidr must be an IP address or network': '请填写 IP 或网段',
  'note is required (at most 200 characters)': '请填写授权说明（最多 200 个字符）',
  'name is required (at most 100 characters)': '请填写名称（最多 100 个字符）',
  'run is not awaiting approval': '该任务不在待批准状态，可能已开始或已失效',
  'weak password checks must be started from Security Validation': '弱口令检测请在“安全验证”页发起',
  'no running honeypot: enable a honeypot on a probe first': '没有运行中的蜜罐：请先在“蜜罐”页为探针启用蜜罐',
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`
  const resp = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (resp.status === 204) return null
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    const msg = (lang === 'zh' && messages[data.error]) || data.error || t('请求失败 ({status})', { status: resp.status })
    if (resp.status === 401 && path !== '/auth/login') {
      clearSession()
      router.push({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
    }
    ElMessage.error(msg)
    throw new Error(msg)
  }
  return data
}

export const api = {
  login: (username, password) => request('POST', '/auth/login', { username, password }),
  logout: () => request('POST', '/auth/logout'),
  changePassword: (old_password, new_password) => request('POST', '/auth/password', { old_password, new_password }),
  stats: () => request('GET', '/stats'),
  assets: () => request('GET', '/assets'),
  tasks: () => request('GET', '/tasks'),
  createTask: (task) => request('POST', '/tasks', task),
  alerts: (status = '') => request('GET', `/alerts${status ? `?status=${status}` : ''}`),
  ackAlert: (id, body) => request('POST', `/alerts/${id}/ack`, body),
  rules: () => request('GET', '/rules'),
  honeypots: () => request('GET', '/honeypots'),
  setHoneypot: (probe, cfg) => request('PUT', `/honeypots/${encodeURIComponent(probe)}`, cfg),
  honeypotEvents: () => request('GET', '/honeypot-events'),
  simulations: () => request('GET', '/simulations'),
  createSimulations: (agent_id, scenarios) => request('POST', '/simulations', { agent_id, scenarios }),
  vulns: (filter) => request('GET', `/vulns?${new URLSearchParams(filter)}`),
  setVulnStatus: (id, status) => request('POST', `/vulns/${id}/status`, { status }),
  agents: () => request('GET', '/agents'),
  incidents: (status = '') => request('GET', `/incidents${status ? `?status=${status}` : ''}`),
  incident: (id) => request('GET', `/incidents/${id}`),
  updateIncident: (id, body) => request('PATCH', `/incidents/${id}`, body),
  addIncidentNote: (id, body) => request('POST', `/incidents/${id}/notes`, { body }),
  version: () => request('GET', '/version'),
  upgrades: () => request('GET', '/upgrades'),
  setUpgradePolicy: (p) => request('PUT', '/upgrades/policy', p),
  queueUpgrades: (agent_ids) => request('POST', '/upgrades', { agent_ids }),
  groups: () => request('GET', '/groups'),
  saveGroup: (g) => (g.id ? request('PUT', `/groups/${g.id}`, g) : request('POST', '/groups', g)),
  deleteGroup: (id) => request('DELETE', `/groups/${id}`),
  setAssetMeta: (ip, meta) => request('PUT', `/assets/${encodeURIComponent(ip)}/meta`, meta),
  intel: (q = '') => request('GET', `/intel${q ? `?q=${encodeURIComponent(q)}` : ''}`),
  addIndicators: (body) => request('POST', '/intel/indicators', body),
  deleteIndicator: (id) => request('DELETE', `/intel/indicators/${id}`),
  feeds: () => request('GET', '/intel/feeds'),
  createFeed: (f) => request('POST', '/intel/feeds', f),
  updateFeed: (id, enabled) => request('PATCH', `/intel/feeds/${id}`, { enabled }),
  deleteFeed: (id) => request('DELETE', `/intel/feeds/${id}`),
  refreshFeed: (id) => request('POST', `/intel/feeds/${id}/refresh`),
  netConfig: () => request('GET', '/intel/net-config'),
  setNetConfig: (c) => request('PUT', '/intel/net-config', c),
  validationScopes: () => request('GET', '/validation/scopes'),
  addValidationScope: (s) => request('POST', '/validation/scopes', s),
  deleteValidationScope: (id) => request('DELETE', `/validation/scopes/${id}`),
  validationRuns: () => request('GET', '/validation/runs'),
  createValidationRun: (r) => request('POST', '/validation/runs', r),
  approveValidationRun: (id) => request('POST', `/validation/runs/${id}/approve`),
  validationReport: (id) => request('GET', `/validation/runs/${id}/report`),
  actions: () => request('GET', '/actions'),
  createAction: (a) => request('POST', '/actions', a),
  approveAction: (id) => request('POST', `/actions/${id}/approve`),
  rollbackAction: (id, reason) => request('POST', `/actions/${id}/rollback`, { reason }),
  hostEvents: (filter) => request('GET', `/host-events?${new URLSearchParams(filter)}`),
  idsEvents: (filter) => request('GET', `/ids/events?${new URLSearchParams(filter)}`),
  suppressions: () => request('GET', '/ids/suppressions'),
  createSuppression: (sp) => request('POST', '/ids/suppressions', sp),
  deleteSuppression: (id) => request('DELETE', `/ids/suppressions/${id}`),
  nodes: () => request('GET', '/nodes'),
  revokeNode: (kind, id) => request('POST', `/nodes/${kind}/${encodeURIComponent(id)}/revoke`),
  enrollTokens: () => request('GET', '/enroll-tokens'),
  installInfo: () => request('GET', '/install-info'),
  createEnrollToken: (t) => request('POST', '/enroll-tokens', t),
  deleteEnrollToken: (id) => request('DELETE', `/enroll-tokens/${id}`),
  channels: () => request('GET', '/notify-channels'),
  createChannel: (c) => request('POST', '/notify-channels', c),
  setChannelEnabled: (id, enabled) => request('POST', `/notify-channels/${id}/enabled`, { enabled }),
  testChannel: (id) => request('POST', `/notify-channels/${id}/test`),
  deleteChannel: (id) => request('DELETE', `/notify-channels/${id}`),
  audit: (filter) => request('GET', `/audit?${new URLSearchParams(filter)}`),
  users: () => request('GET', '/users'),
  createUser: (user) => request('POST', '/users', user),
  deleteUser: (id) => request('DELETE', `/users/${id}`),
  apiTokens: () => request('GET', '/api-tokens'),
  createAPIToken: (name) => request('POST', '/api-tokens', { name }),
  deleteAPIToken: (id) => request('DELETE', `/api-tokens/${id}`),
}
