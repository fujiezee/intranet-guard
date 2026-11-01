// 控制台界面语言。以中文原文作为键：t('保存') 在英文下查 locales/en.js，中文下原样返回。
// 切换语言时刷新页面，所以 t() 不需要是响应式的，模块级常量里也可以直接使用。
import en from './locales/en'

const KEY = 'safe.lang'

function stored() {
  try {
    return localStorage.getItem(KEY)
  } catch {
    return null
  }
}

export const lang = stored() === 'zh' ? 'zh' : 'en' // 默认英文

export function setLang(l) {
  try {
    localStorage.setItem(KEY, l)
  } catch {
    // 浏览器禁用存储时只影响记住语言
  }
  location.reload()
}

// t('共 {n} 台', { n: 3 })
export function t(text, params) {
  const s = lang === 'en' ? (en[text] ?? text) : text
  return params ? s.replace(/\{(\w+)\}/g, (m, k) => (k in params ? params[k] : m)) : s
}
