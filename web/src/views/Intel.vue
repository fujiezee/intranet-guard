<template>
  <div>
    <div class="page-header">
      <h2>威胁情报</h2>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px">
      情报下发到各探针，与 Suricata 输出的 DNS 查询、TLS / HTTP 访问的域名、连接地址比对；管理中心同时比对登录来源和 IDS 告警中的地址。
      探针需要读取完整的 <span class="mono">eve.json</span>（含 dns、tls、http、flow 记录）。
    </el-alert>

    <el-tabs v-model="tab">
      <el-tab-pane label="情报列表" name="list">
        <div class="tools">
          <el-input v-model="q" placeholder="搜索 IP / 域名" clearable style="width: 240px" @change="load" />
          <span class="sub">
            共 {{ total }} 条<template v-for="(n, src) in counts" :key="src">，{{ sourceName(src) }} {{ n }}</template>
          </span>
          <el-button v-if="auth.isAdmin" type="primary" style="margin-left: auto" @click="importDialog = true">导入</el-button>
        </div>
        <el-table :data="indicators" v-loading="loading" stripe empty-text="没有情报">
          <el-table-column label="类型" width="80"><template #default="{ row }">{{ typeNames[row.type] }}</template></el-table-column>
          <el-table-column label="值" min-width="220"><template #default="{ row }"><span class="mono">{{ row.value }}</span></template></el-table-column>
          <el-table-column label="级别" width="70"><template #default="{ row }"><SeverityTag :severity="row.severity" /></template></el-table-column>
          <el-table-column label="来源" width="140"><template #default="{ row }">{{ sourceName(row.source) }}</template></el-table-column>
          <el-table-column prop="note" label="备注" min-width="160" />
          <el-table-column label="添加时间" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
          <el-table-column v-if="auth.isAdmin" width="80">
            <template #default="{ row }">
              <el-button v-if="row.source === 'manual'" size="small" link type="danger" @click="remove(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <p class="sub">内置自检域名 <span class="mono">{{ simDomain }}</span> 始终下发，用于“情报命中”攻击模拟自检。</p>
      </el-tab-pane>

      <el-tab-pane label="订阅源" name="feeds">
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px"
          title="订阅源由管理中心每 6 小时拉取一次，需要管理中心能访问外网。格式为纯文本，每行一个 IP / 网段 / 域名，兼容 hosts 文件。" />
        <el-table :data="feeds" stripe empty-text="没有订阅源">
          <el-table-column prop="name" label="名称" width="160" />
          <el-table-column label="地址" min-width="260"><template #default="{ row }"><span class="mono small">{{ row.url }}</span></template></el-table-column>
          <el-table-column label="级别" width="70"><template #default="{ row }"><SeverityTag :severity="row.severity" /></template></el-table-column>
          <el-table-column prop="count" label="条目" width="80" />
          <el-table-column label="最近拉取" width="200">
            <template #default="{ row }">
              <span v-if="row.last_fetch">{{ formatTime(row.last_fetch) }}</span>
              <span v-else class="sub">未拉取</span>
              <div v-if="row.last_error" class="err">{{ row.last_error }}</div>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="70">
            <template #default="{ row }">
              <el-switch :model-value="row.enabled" :disabled="!auth.isAdmin" @change="(v) => toggle(row, v)" />
            </template>
          </el-table-column>
          <el-table-column v-if="auth.isAdmin" width="130">
            <template #default="{ row }">
              <el-button size="small" link :loading="refreshing === row.id" @click="refresh(row)">立即拉取</el-button>
              <el-button size="small" link type="danger" @click="removeFeed(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="auth.isAdmin" class="feed-form">
          <el-input v-model="feedForm.name" placeholder="名称" style="width: 160px" />
          <el-input v-model="feedForm.url" placeholder="https://…" style="width: 380px" />
          <el-select v-model="feedForm.severity" style="width: 90px">
            <el-option label="高" value="high" />
            <el-option label="中" value="medium" />
          </el-select>
          <el-button @click="addFeed">添加并启用</el-button>
        </div>
        <p class="sub">
          常用的公开情报源（请自行评估可信度与使用条款）：
          <el-link v-for="p in presets" :key="p.url" type="primary" :underline="false" class="preset" @click="Object.assign(feedForm, p)">{{ p.name }}</el-link>
        </p>
      </el-tab-pane>

      <el-tab-pane label="分析参数" name="config">
        <el-form label-width="140px" style="max-width: 680px">
          <el-form-item label="工作时间">
            <el-input-number v-model="cfg.work_start" :min="0" :max="23" :disabled="!auth.isAdmin" /> 时 至
            <el-input-number v-model="cfg.work_end" :min="1" :max="24" :disabled="!auth.isAdmin" /> 时
            <div class="sub">非工作时间的大流量外发视为疑似外传（探针本地时区）。</div>
          </el-form-item>
          <el-form-item label="外传阈值（MB / 小时）">
            <el-input-number v-model="exfilMB" :min="0" :step="100" :disabled="!auth.isAdmin" />
            <div class="sub">单台主机 1 小时内发往外网的数据量；0 表示不检测。</div>
          </el-form-item>
          <el-form-item label="允许的域名后缀">
            <el-input v-model="allowText" type="textarea" :rows="5" :disabled="!auth.isAdmin" placeholder="每行一个，如 sophosxl.net" />
            <div class="sub">这些域名不做 DNS 隧道分析（杀毒软件、邮件反垃圾等会产生大量长子域名查询）。</div>
          </el-form-item>
          <el-form-item v-if="auth.isAdmin"><el-button type="primary" @click="saveConfig">保存</el-button></el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="importDialog" title="导入情报" width="560px">
      <el-input v-model="importForm.text" type="textarea" :rows="10" placeholder="每行一个 IP、网段或域名；支持 # 注释和 hosts 文件格式" />
      <div class="import-opts">
        <el-select v-model="importForm.severity" style="width: 100px">
          <el-option label="高危" value="high" />
          <el-option label="中危" value="medium" />
        </el-select>
        <el-input v-model="importForm.note" placeholder="备注（如来源：演练通报）" />
      </div>
      <template #footer>
        <el-button @click="importDialog = false">取消</el-button>
        <el-button type="primary" :disabled="!importForm.text.trim()" @click="doImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const typeNames = { ip: 'IP', cidr: '网段', domain: '域名' }
const presets = [
  { name: 'Feodo Tracker（C2 IP）', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', severity: 'high' },
  { name: 'URLhaus（恶意域名）', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', severity: 'medium' },
  { name: 'ThreatFox（IOC 域名）', url: 'https://threatfox.abuse.ch/downloads/hostfile/', severity: 'high' },
]

const tab = ref('list')
const q = ref('')
const indicators = ref([])
const counts = ref({})
const simDomain = ref('')
const feeds = ref([])
const loading = ref(false)
const refreshing = ref(0)
const importDialog = ref(false)
const importForm = reactive({ text: '', severity: 'high', note: '' })
const feedForm = reactive({ name: '', url: '', severity: 'high' })
const cfg = reactive({ work_start: 7, work_end: 22, exfil_bytes: 1 << 30, allow: [] })
const exfilMB = ref(1024)
const allowText = ref('')

const total = computed(() => Object.values(counts.value).reduce((a, b) => a + b, 0))
const sourceName = (src) => {
  if (src === 'manual') return '自定义'
  const f = feeds.value.find((f) => `feed:${f.id}` === src)
  return f ? f.name : src
}

async function load() {
  loading.value = true
  try {
    const [d, f] = await Promise.all([api.intel(q.value), api.feeds()])
    indicators.value = d.indicators
    counts.value = d.counts
    simDomain.value = d.sim_domain
    feeds.value = f
  } finally {
    loading.value = false
  }
}

async function loadConfig() {
  Object.assign(cfg, await api.netConfig())
  exfilMB.value = Math.round(cfg.exfil_bytes / (1 << 20))
  allowText.value = (cfg.allow || []).join('\n')
}

async function doImport() {
  const r = await api.addIndicators({ ...importForm })
  ElMessage.success(`识别 ${r.parsed} 条，新增 ${r.added} 条`)
  importDialog.value = false
  importForm.text = ''
  load()
}

async function remove(row) {
  await api.deleteIndicator(row.id)
  load()
}

async function addFeed() {
  await api.createFeed({ ...feedForm, enabled: true })
  ElMessage.success('已添加，正在后台拉取')
  Object.assign(feedForm, { name: '', url: '', severity: 'high' })
  setTimeout(load, 3000)
  load()
}

async function toggle(row, enabled) {
  await api.updateFeed(row.id, enabled)
  load()
}

async function refresh(row) {
  refreshing.value = row.id
  try {
    const f = await api.refreshFeed(row.id)
    if (f.last_error) ElMessage.error(`拉取失败：${f.last_error}`)
    else ElMessage.success(`已更新，${f.count} 条`)
    load()
  } finally {
    refreshing.value = 0
  }
}

async function removeFeed(row) {
  try {
    await ElMessageBox.confirm(`删除订阅源“${row.name}”及其 ${row.count} 条情报？`, '删除订阅源', { type: 'warning' })
  } catch {
    return
  }
  await api.deleteFeed(row.id)
  load()
}

async function saveConfig() {
  await api.setNetConfig({
    work_start: cfg.work_start,
    work_end: cfg.work_end,
    exfil_bytes: exfilMB.value * (1 << 20),
    allow: allowText.value.split('\n').map((s) => s.trim()).filter(Boolean),
  })
  ElMessage.success('已保存，探针在 15 秒内生效')
  loadConfig()
}

onMounted(() => {
  load()
  loadConfig()
})
</script>

<style scoped>
.tools { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.sub { color: #909399; font-size: 12px; }
.small { font-size: 12px; }
.err { color: #f56c6c; font-size: 12px; }
.feed-form { display: flex; gap: 8px; margin-top: 12px; }
.preset { margin-left: 10px; font-size: 12px; }
.import-opts { display: flex; gap: 8px; margin-top: 8px; }
</style>
