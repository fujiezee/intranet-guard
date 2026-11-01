<template>
  <div>
    <div class="page-header">
      <h2>{{ t('漏洞') }}</h2>
      <div class="tools">
        <el-radio-group v-model="filter.status" @change="load">
          <el-radio-button value="open">{{ t('未修复') }}</el-radio-button>
          <el-radio-button value="ignored">{{ t('已忽略') }}</el-radio-button>
          <el-radio-button value="fixed">{{ t('已修复') }}</el-radio-button>
          <el-radio-button value="">{{ t('全部') }}</el-radio-button>
        </el-radio-group>
        <el-select v-model="filter.severity" :placeholder="t('全部级别')" clearable style="width: 120px" @change="load">
          <el-option :label="t('高')" value="high" />
          <el-option :label="t('中')" value="medium" />
          <el-option :label="t('低')" value="low" />
        </el-select>
        <el-input v-model="filter.ip" placeholder="IP" clearable style="width: 150px" @change="load" />
        <el-button @click="load">{{ t('刷新') }}</el-button>
      </div>
    </div>

    <el-table :data="vulns" v-loading="loading" stripe :empty-text="t('暂无漏洞。在扫描任务中新建“漏洞检测”任务进行检查')">
      <el-table-column :label="t('级别')" width="70">
        <template #default="{ row }"><SeverityTag :severity="row.severity" /></template>
      </el-table-column>
      <el-table-column :label="t('资产')" width="170">
        <template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.port }}</span></template>
      </el-table-column>
      <el-table-column :label="t('漏洞')" min-width="380">
        <template #default="{ row }">
          <div class="title">{{ row.title }}</div>
          <div class="sub">{{ row.detail }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('状态')" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="statusMap[row.status].type">{{ statusMap[row.status].label }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('首次发现')" width="170"><template #default="{ row }">{{ formatTime(row.first_seen) }}</template></el-table-column>
      <el-table-column :label="t('最近确认')" width="170">
        <template #default="{ row }">{{ row.status === 'fixed' ? formatTime(row.fixed_at) + t(' 修复') : formatTime(row.last_seen) }}</template>
      </el-table-column>
      <el-table-column v-if="auth.isAdmin" :label="t('操作')" width="90">
        <template #default="{ row }">
          <el-button v-if="row.status === 'open'" size="small" link @click="setStatus(row, 'ignored')">{{ t('忽略') }}</el-button>
          <el-button v-else-if="row.status === 'ignored'" size="small" link type="primary" @click="setStatus(row, 'open')">{{ t('取消忽略') }}</el-button>
        </template>
      </el-table-column>
    </el-table>
    <p class="hint">{{ t('漏洞修复后无需手动关闭：再次执行漏洞检测时，检查通过或端口已关闭的漏洞会自动标记为已修复。') }}</p>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const statusMap = {
  open: { label: t('未修复'), type: 'danger' },
  ignored: { label: t('已忽略'), type: 'info' },
  fixed: { label: t('已修复'), type: 'success' },
}

const vulns = ref([])
const loading = ref(false)
const filter = reactive({ status: 'open', severity: '', ip: '' })

async function load() {
  loading.value = true
  try {
    vulns.value = await api.vulns(Object.fromEntries(Object.entries(filter).filter(([, v]) => v)))
  } finally {
    loading.value = false
  }
}

async function setStatus(row, status) {
  if (status === 'ignored') {
    try {
      await ElMessageBox.confirm(t('忽略后再次发现 {p0}:{p1} 的“{p2}”也不会告警。确定忽略？', { p0: row.ip, p1: row.port, p2: row.title }), t('忽略漏洞'), { type: 'warning' })
    } catch {
      return
    }
  }
  await api.setVulnStatus(row.id, status)
  ElMessage.success(status === 'ignored' ? t('已忽略') : t('已重新打开'))
  load()
}

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.title { font-weight: 500; }
.sub { color: #909399; font-size: 12px; margin-top: 2px; }
.hint { color: #909399; font-size: 12px; margin-top: 12px; }
</style>
