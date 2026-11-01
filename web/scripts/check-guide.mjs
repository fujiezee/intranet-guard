// 检查使用指南（docs/GUIDE.md）：控制台每个页面都有对应章节（页面右上角"帮助"按路由名跳转），文内链接都能打开。
import { readFileSync } from 'node:fs'
import { marked } from 'marked'

const guide = readFileSync(new URL('../../docs/GUIDE.md', import.meta.url), 'utf8')
const router = readFileSync(new URL('../src/router.js', import.meta.url), 'utf8')
const anchors = new Set([...guide.matchAll(/<a id="([\w-]+)"><\/a>/g)].map((m) => m[1]))
const routes = [...router.matchAll(/name: '([\w-]+)'/g)].map((m) => m[1]).filter((n) => !['login', 'help'].includes(n))
const missing = routes.filter((r) => !anchors.has(r))
// 与 Help.vue 相同：指向其他 .md 的链接在控制台中只保留文字
const html = marked.parse(guide.replace(/\[([^\]]+)\]\((?!#)[^)]*\.md(#[^)]*)?\)/g, '$1'))
const broken = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]).filter((h) => !(h.startsWith('#') && anchors.has(h.slice(1))))
if (missing.length || broken.length) {
  console.error('页面缺少使用指南章节：', missing, '无法打开的链接：', broken)
  process.exit(1)
}
console.log(`使用指南检查通过：${anchors.size} 个章节覆盖 ${routes.length} 个页面`)
