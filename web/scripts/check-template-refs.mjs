// 检查 .vue 模板只引用脚本中定义的变量：未定义的变量运行时只是空值，页面悄悄缺一块，构建和浏览器都不报错。
// 用 <script setup> 内联编译：脚本中定义的变量被直接引用，其余的才会编译成 _ctx.xxx。
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { compileScript, parse } from '@vue/compiler-sfc'

// 模板中的全局对象（Vue 的内置变量和组件）
const allowed = new Set(['$event', '$attrs', '$slots', '$props', '$emit', '$route', '$router'])

function vueFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name)
    return e.isDirectory() ? vueFiles(p) : p.endsWith('.vue') ? [p] : []
  })
}

let bad = 0
for (const file of vueFiles('src')) {
  const { descriptor } = parse(readFileSync(file, 'utf8'), { filename: file })
  if (!descriptor.scriptSetup || !descriptor.template) continue
  const { content } = compileScript(descriptor, { id: file, inlineTemplate: true })
  const refs = new Set([...content.matchAll(/\b_ctx\.([$\w]+)/g)].map((m) => m[1]).filter((n) => !allowed.has(n)))
  for (const name of refs) {
    console.error(`${file}: template uses undefined "${name}"`)
    bad++
  }
}
if (bad) process.exit(1)
console.log('template references ok')
