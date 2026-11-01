<template>
  <div class="help">
    <aside class="toc">
      <div class="toc-title">使用指南</div>
      <a v-for="s in sections" :key="s.id" :class="{ on: s.id === active }" :href="`#${s.id}`" @click.prevent="go(s.id)">{{ s.title }}</a>
    </aside>
    <!-- 内容来自仓库中的 docs/GUIDE.md（构建时嵌入），不含用户输入 -->
    <article ref="body" class="doc" @click="onClick" v-html="html" />
  </div>
</template>

<script setup>
import { nextTick, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { marked } from 'marked'
import guide from '../../../docs/GUIDE.md?raw'

const route = useRoute()
const router = useRouter()
const body = ref(null)
const active = ref('')

// 指向仓库内其他文档（README、ARCHITECTURE 等）的链接在控制台中无法打开，只保留文字
const html = marked.parse(guide.replace(/\[([^\]]+)\]\((?!#)[^)]*\.md(#[^)]*)?\)/g, '$1'))

// 目录：每个章节标题前有 <a id="…">
const sections = []
for (const m of guide.matchAll(/<a id="([\w-]+)"><\/a>\s*\n## (.+)/g)) sections.push({ id: m[1], title: m[2] })

function go(id, smooth = true) {
  const el = body.value?.querySelector(`#${CSS.escape(id)}`)
  if (!el) return
  el.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' })
  active.value = id
  if (route.hash !== `#${id}`) router.replace({ hash: `#${id}` })
}

// 文中的 #锚点链接在本页滚动，不交给浏览器（避免整页跳动）
function onClick(e) {
  const a = e.target.closest('a')
  const href = a?.getAttribute('href') || ''
  if (href.startsWith('#')) {
    e.preventDefault()
    go(href.slice(1))
  }
}

async function fromHash() {
  await nextTick()
  if (route.hash) go(route.hash.slice(1), false)
}

onMounted(fromHash)
watch(() => route.hash, (h) => h && h.slice(1) !== active.value && fromHash())
</script>

<style scoped>
.help { display: flex; gap: 24px; align-items: flex-start; }
.toc { position: sticky; top: 0; width: 170px; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid #ebeef5; padding-right: 12px; }
.toc-title { font-weight: 600; margin-bottom: 8px; }
.toc a { color: #606266; text-decoration: none; font-size: 13px; padding: 4px 6px; border-radius: 3px; }
.toc a:hover { background: #f5f7fa; }
.toc a.on { color: #409eff; background: #ecf5ff; }
.doc { flex: 1; min-width: 0; max-width: 900px; line-height: 1.75; color: #303133; }
.doc :deep(h1) { font-size: 22px; margin-top: 0; }
.doc :deep(h2) { font-size: 18px; margin-top: 32px; padding-bottom: 6px; border-bottom: 1px solid #ebeef5; scroll-margin-top: 12px; }
.doc :deep(a[id]) { position: relative; top: -12px; }
.doc :deep(table) { border-collapse: collapse; margin: 8px 0 16px; font-size: 13px; }
.doc :deep(th), .doc :deep(td) { border: 1px solid #ebeef5; padding: 6px 10px; text-align: left; vertical-align: top; }
.doc :deep(th) { background: #f5f7fa; }
.doc :deep(code) { background: #f5f7fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.doc :deep(strong) { color: #c45656; font-weight: 600; }
</style>
