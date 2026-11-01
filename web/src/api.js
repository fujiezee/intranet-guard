import { ElMessage } from 'element-plus'
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
    const msg = messages[data.error] || data.error || `请求失败 (${resp.status})`
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
  ackAlert: (id) => request('POST', `/alerts/${id}/ack`),
  vulns: (filter) => request('GET', `/vulns?${new URLSearchParams(filter)}`),
  setVulnStatus: (id, status) => request('POST', `/vulns/${id}/status`, { status }),
  agents: () => request('GET', '/agents'),
  hostEvents: (filter) => request('GET', `/host-events?${new URLSearchParams(filter)}`),
  idsEvents: (filter) => request('GET', `/ids/events?${new URLSearchParams(filter)}`),
  suppressions: () => request('GET', '/ids/suppressions'),
  createSuppression: (sp) => request('POST', '/ids/suppressions', sp),
  deleteSuppression: (id) => request('DELETE', `/ids/suppressions/${id}`),
  nodes: () => request('GET', '/nodes'),
  revokeNode: (kind, id) => request('POST', `/nodes/${kind}/${encodeURIComponent(id)}/revoke`),
  enrollTokens: () => request('GET', '/enroll-tokens'),
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
}
