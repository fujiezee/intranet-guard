<template>
  <div>
    <div class="page-header">
      <h2>资产（{{ filtered.length }}）</h2>
      <div class="tools">
        <el-input v-model="keyword" placeholder="搜索 IP / 主机名 / 端口 / 服务" clearable style="width: 280px" />
        <el-button @click="load">刷新</el-button>
      </div>
    </div>
    <el-table :data="filtered" v-loading="loading" stripe @row-click="(row) => (current = row)" row-class-name="clickable">
      <el-table-column label="IP" width="150" sortable :sort-method="(a, b) => compareIP(a.ip, b.ip)">
        <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
      </el-table-column>
      <el-table-column prop="hostname" label="主机名" min-width="160" />
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
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { compareIP, formatTime } from '../format'

// 与后端 internal/alert 中的高危端口保持一致，用于高亮显示。
const riskyPorts = new Set([23, 2375, 5900, 6379, 9200, 11211, 27017, 21, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5985])

const assets = ref([])
const loading = ref(false)
const keyword = ref('')
const current = ref(null)

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
:deep(.clickable) { cursor: pointer; }
h4 { margin: 20px 0 8px; }
</style>
