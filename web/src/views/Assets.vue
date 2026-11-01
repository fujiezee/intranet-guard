<template>
  <div>
    <div class="page-header">
      <h2>资产（{{ filtered.length }}）</h2>
      <div class="tools">
        <el-input v-model="keyword" placeholder="搜索 IP / 主机名 / 端口 / 服务" clearable style="width: 280px" />
        <el-button @click="load">刷新</el-button>
      </div>
    </div>
    <el-table :data="filtered" v-loading="loading" stripe @row-click="select" row-class-name="clickable">
      <el-table-column label="IP" width="150" sortable :sort-method="(a, b) => compareIP(a.ip, b.ip)">
        <template #default="{ row }">
          <span class="mono">{{ row.ip }}</span>
          <el-tag v-if="row.honeypot" size="small" type="warning" style="margin-left: 4px">蜜罐</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="风险" width="90" sortable :sort-method="(a, b) => a.risk - b.risk">
        <template #default="{ row }">
          <el-tooltip :disabled="!row.risk_reasons?.length" placement="right">
            <template #content><div v-for="r in row.risk_reasons" :key="r">{{ r }}</div></template>
            <el-tag size="small" :type="riskType(row.risk)" effect="dark">{{ row.risk }}</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="主机名 / 负责人" min-width="170">
        <template #default="{ row }">
          <div>{{ row.hostname }}</div>
          <div class="sub">
            <el-tag v-if="row.importance === 'core'" size="small" type="danger" effect="plain">核心</el-tag>
            <el-tag v-else-if="row.importance === 'important'" size="small" type="warning" effect="plain">重要</el-tag>
            {{ row.owner }}
            <el-tag v-for="t in row.tags || []" :key="t" size="small" type="info" class="tag">{{ t }}</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="开放端口" min-width="300">
        <template #default="{ row }">
          <el-tag v-for="p in row.ports" :key="p.port" size="small" :type="riskyPorts.has(p.port) ? 'danger' : ''" class="port">
            {{ p.port }}{{ p.service ? '/' + p.service : '' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="probe_id" label="探针" width="110" />
      <el-table-column label="首次发现" width="170" sortable :sort-method="(a, b) => a.first_seen.localeCompare(b.first_seen)">
        <template #default="{ row }">{{ formatTime(row.first_seen) }}</template>
      </el-table-column>
      <el-table-column label="最后在线" width="170" sortable :sort-method="(a, b) => a.last_seen.localeCompare(b.last_seen)">
        <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
      </el-table-column>
    </el-table>

    <el-drawer :model-value="!!current" @close="current = null" :title="current?.ip" size="560px">
      <template v-if="current">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="主机名">{{ current.hostname || '-' }}</el-descriptions-item>
          <el-descriptions-item label="风险">
            <el-tag size="small" :type="riskType(current.risk)" effect="dark">{{ current.risk }}</el-tag>
            <span class="sub" style="margin-left: 6px">{{ (current.risk_reasons || []).join('；') || '无' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="重要性 / 负责人 / 标签">
            <template v-if="auth.isAdmin">
              <div class="meta">
                <el-select v-model="meta.importance" size="small" style="width: 90px">
                  <el-option label="普通" value="normal" />
                  <el-option label="重要" value="important" />
                  <el-option label="核心" value="core" />
                </el-select>
                <el-input v-model="meta.owner" size="small" placeholder="负责人" style="width: 110px" />
                <el-input v-model="meta.tags" size="small" placeholder="标签，逗号分隔" style="width: 150px" />
                <el-button size="small" @click="saveMeta">保存</el-button>
              </div>
            </template>
            <template v-else>{{ current.importance }} {{ current.owner }} {{ (current.tags || []).join(', ') }}</template>
          </el-descriptions-item>
          <el-descriptions-item label="探针">{{ current.probe_id }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatTime(current.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="最后在线">{{ formatTime(current.last_seen) }}</el-descriptions-item>
        </el-descriptions>
        <h4>开放端口</h4>
        <el-table :data="current.ports" size="small" empty-text="没有开放端口">
          <el-table-column prop="port" label="端口" width="70" />
          <el-table-column prop="proto" label="协议" width="60" />
          <el-table-column prop="service" label="服务" width="110" />
          <el-table-column label="Banner">
            <template #default="{ row }"><span class="mono">{{ row.banner }}</span></template>
          </el-table-column>
        </el-table>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { compareIP, formatTime } from '../format'

// 与后端 internal/alert 中的高危端口保持一致，用于高亮显示。
const riskyPorts = new Set([23, 2375, 5900, 6379, 9200, 11211, 27017, 21, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5985])

const assets = ref([])
const loading = ref(false)
const keyword = ref('')
const current = ref(null)
const meta = reactive({ importance: 'normal', owner: '', tags: '' })
const riskType = (r) => (r >= 60 ? 'danger' : r >= 30 ? 'warning' : r > 0 ? 'info' : 'success')

function select(row) {
  current.value = row
  Object.assign(meta, { importance: row.importance || 'normal', owner: row.owner || '', tags: (row.tags || []).join(', ') })
}

async function saveMeta() {
  await api.setAssetMeta(current.value.ip, {
    importance: meta.importance,
    owner: meta.owner,
    tags: meta.tags.split(/[,，]/).map((t) => t.trim()).filter(Boolean),
  })
  ElMessage.success('已保存')
  await load()
  select(assets.value.find((a) => a.ip === current.value.ip))
}

const filtered = computed(() => {
  const k = keyword.value.trim().toLowerCase()
  if (!k) return assets.value
  return assets.value.filter(
    (a) =>
      a.ip.includes(k) ||
      (a.hostname || '').toLowerCase().includes(k) ||
      a.ports.some((p) => String(p.port) === k || (p.service || '').toLowerCase().includes(k)),
  )
})

async function load() {
  loading.value = true
  try {
    assets.value = (await api.assets()).sort((a, b) => compareIP(a.ip, b.ip))
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.port { margin: 2px 4px 2px 0; }
.sub { color: #909399; font-size: 12px; }
.tag { margin-left: 4px; }
.meta { display: flex; gap: 6px; flex-wrap: wrap; }
:deep(.clickable) { cursor: pointer; }
h4 { margin: 20px 0 8px; }
</style>
