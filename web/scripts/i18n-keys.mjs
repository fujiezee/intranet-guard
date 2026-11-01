// 列出代码中所有 t('…') 的文案。
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

export function sourceFiles(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    if (statSync(p).isDirectory()) return f === 'locales' ? [] : sourceFiles(p)
    return /\.(vue|js)$/.test(f) ? [p] : []
  })
}

export function keys(dir) {
  const out = new Set()
  for (const f of sourceFiles(dir)) {
    for (const m of readFileSync(f, 'utf8').matchAll(/\bt\('((?:[^'\\]|\\.)*)'/g)) out.add(m[1].replace(/\\(.)/g, '$1'))
  }
  return [...out]
}
