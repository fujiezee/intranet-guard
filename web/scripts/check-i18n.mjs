// 检查控制台英文文案：代码中的每条中文 t('…') 都有英文翻译，且翻译里不含中文；模板和脚本中没有未经 t() 的中文。
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import en from '../src/locales/en.js'
import { keys, sourceFiles } from './i18n-keys.mjs'

const src = fileURLToPath(new URL('../src', import.meta.url))
const han = /[一-鿿]/
const missing = keys(src).filter((k) => han.test(k) && !(k in en))
const notEnglish = Object.entries(en).filter(([, v]) => han.test(v)).map(([k]) => k)
const raw = []
for (const f of sourceFiles(src)) {
  if (/(i18n|api)\.js$/.test(f)) continue // api.js 是中文模式下的错误提示映射
  readFileSync(f, 'utf8').replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' ')).split('\n').forEach((line, i) => {
    const code = line.replace(/(^|\s)\/\/.*$/, '').replace(/'中文'/g, '').replace(/\bt\('(?:[^'\\]|\\.)*'/g, '')
    if (han.test(code)) raw.push(`${f}:${i + 1}: ${line.trim()}`)
  })
}
if (missing.length || notEnglish.length || raw.length) {
  console.error('缺少英文翻译：', missing, '翻译含中文：', notEnglish, '未经 t() 的中文：', raw)
  process.exit(1)
}
console.log(`界面文案检查通过：${Object.keys(en).length} 条`)
