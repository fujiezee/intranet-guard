import { reactive } from 'vue'

// 会话 token 存在 localStorage，刷新页面后保持登录。
export const auth = reactive({
  token: localStorage.getItem('safe_token') || '',
  user: JSON.parse(localStorage.getItem('safe_user') || 'null'),
  get isAdmin() {
    return this.user?.role === 'admin'
  },
})

export function setSession(token, user) {
  auth.token = token
  auth.user = user
  localStorage.setItem('safe_token', token)
  localStorage.setItem('safe_user', JSON.stringify(user))
}

export function clearSession() {
  auth.token = ''
  auth.user = null
  localStorage.removeItem('safe_token')
  localStorage.removeItem('safe_user')
}
