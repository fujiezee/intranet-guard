<template>
  <div>
    <div class="page-header">
      <h2>流量检测</h2>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-tabs v-model="tab">
      <el-tab-pane label="检测事件" name="events">
        <div class="filters">
          <el-select v-model="filter.max_severity" style="width: 140px" @change="loadEvents">
            <el-option label="全部优先级" :value="0" />
            <el-option label="高 + 中" :value="2" />
            <el-option label="仅高" :value="1" />
          </el-select>
          <el-input v-model="filter.src_ip" placeholder="源 IP" clearable style="width: 150px" @change="loadEvents" />
          <el-input v-model="filter.dest_ip" placeholder="目的 IP" clearable style="width: 150px" @change="loadEvents" />
          <el-input v-model="filter.signature_id" placeholder="规则 ID" clearable style="width: 130px" @change="loadEvents" />
        </div>
        <el-table :data="events" v-loading="loading" size="small" stripe empty-text="暂无事件，确认探针已通过 -eve 接入 Suricata">
          <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.time) }}</template></el-table-column>
          <el-table-column label="优先级" width="70">
            <template #default="{ row }"><SeverityTag :severity="severityName(row.severity)" /></template>
          </el-table-column>
          <el-table-column label="源" width="170">
            <template #default="{ row }"><span class="mono">{{ row.src_ip }}:{{ row.src_port }}</span></template>
          </el-table-column>
          <el-table-column label="目的" width="170">
            <template #default="{ row }"><span class="mono">{{ row.dest_ip }}:{{ row.dest_port }}</span></template>
          </el-table-column>
          <el-table-column label="协议" width="80"><template #default="{ row }">{{ row.app_proto || row.proto }}</template></el-table-column>
          <el-table-column label="规则" min-width="320">
            <template #default="{ row }">
              <div>{{ row.signature }}</div>
              <div class="sub">
                {{ row.signature_id }} · {{ row.category }}
                <el-tag v-if="row.suppressed" size="small" type="info">已抑制</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column v-if="auth.isAdmin" label="操作" width="110">
            <template #default="{ row }">
              <el-dropdown trigger="click" @command="(scope) => suppress(row, scope)">
                <el-button size="small" link type="primary">抑制</el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="src">仅抑制来源 {{ row.src_ip }}</el-dropdown-item>
                    <el-dropdown-item command="all">抑制该规则（所有来源）</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane :label="`抑制规则（${suppressions.length}）`" name="suppressions">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px"
          title="被抑制的事件仍会记录，但不再产生告警。用于处理确认的误报，例如漏洞扫描器、监控系统触发的规则。" />
        <el-table :data="suppressions" size="small" stripe empty-text="暂无抑制规则">
          <el-table-column prop="signature_id" label="规则 ID" width="120" />
          <el-table-column label="来源" width="160">
            <template #default="{ row }"><span class="mono">{{ row.src_ip || '所有来源' }}</span></template>
          </el-table-column>
          <el-table-column prop="note" label="原因" min-width="200" />
          <el-table-column prop="created_by" label="创建人" width="100" />
          <el-table-column label="创建时间" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
          <el-table-column v-if="auth.isAdmin" label="操作" width="80">
            <template #default="{ row }">
              <el-button size="small" link type="danger" @click="removeSuppression(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'
import SeverityTag from '../components/SeverityTag.vue'

const tab = ref('events')
const events = ref([])
const suppressions = ref([])
const loading = ref(false)
const filter = reactive({ max_severity: 2, src_ip: '', dest_ip: '', signature_id: '' })

const severityName = (n) => (n === 1 ? 'high' : n === 2 ? 'medium' : 'low')

async function loadEvents() {
  loading.value = true
  try {
    const params = Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== '' && v !== 0))
    events.value = await api.idsEvents(params)
  } finally {
    loading.value = false
  }
}

async function loadSuppressions() {
  suppressions.value = await api.suppressions()
}

function load() {
  loadEvents()
  loadSuppressions()
}

async function suppress(row, scope) {
  let note
  try {
    const target = scope === 'src' ? `来源 ${row.src_ip} 的` : '所有来源的'
    ;({ value: note } = await ElMessageBox.prompt(`抑制${target}规则 ${row.signature_id}：${row.signature}`, '添加抑制规则', {
      inputPlaceholder: '原因（例如：内部漏洞扫描器）',
    }))
  } catch {
    return // 取消
  }
  await api.createSuppression({ signature_id: row.signature_id, src_ip: scope === 'src' ? row.src_ip : '', note: note || '' })
  ElMessage.success('已添加抑制规则')
  load()
}

async function removeSuppression(row) {
  await api.deleteSuppression(row.id)
  ElMessage.success('已删除，后续事件将恢复告警')
  loadSuppressions()
}

onMounted(load)
</script>

<style scoped>
.filters { display: flex; gap: 8px; margin-bottom: 12px; }
.sub { color: #909399; font-size: 12px; display: flex; align-items: center; gap: 6px; }
</style>
