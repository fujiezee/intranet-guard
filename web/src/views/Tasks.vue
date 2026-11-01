<template>
  <div>
    <div class="page-header">
      <h2>{{ t('扫描任务') }}</h2>
      <div class="tools">
        <el-button @click="load">{{ t('刷新') }}</el-button>
        <el-button v-if="auth.isAdmin" type="primary" @click="openDialog">{{ t('新建任务') }}</el-button>
      </div>
    </div>
    <el-table :data="tasks" v-loading="loading" stripe>
      <el-table-column prop="id" label="ID" width="170"><template #default="{ row }"><span class="mono">{{ row.id }}</span></template></el-table-column>
      <el-table-column prop="probe_id" :label="t('探针')" width="110" />
      <el-table-column :label="t('目标')" min-width="200">
        <template #default="{ row }"><span class="mono">{{ row.targets.join(', ') }}</span></template>
      </el-table-column>
      <el-table-column :label="t('端口数')" width="80"><template #default="{ row }">{{ row.ports.length }}</template></el-table-column>
      <el-table-column :label="t('类型')" width="150">
        <template #default="{ row }">
          <el-tag size="small" :type="row.kind === 'vuln' ? 'warning' : ''">{{ row.kind === 'vuln' ? t('漏洞检测') : t('资产发现') }}</el-tag>
          <el-tag v-if="row.weak_password" size="small" type="danger" class="tag-gap">{{ t('弱口令') }}</el-tag>
          <el-tag v-if="row.baseline" size="small" type="info" class="tag-gap">{{ t('基线') }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('状态')" width="100">
        <template #default="{ row }">
          <el-tooltip :disabled="!row.error" :content="row.error">
            <el-tag size="small" :type="statusMap[row.status]?.type">{{ statusMap[row.status]?.label }}</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column :label="t('创建时间')" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column :label="t('更新时间')" width="170"><template #default="{ row }">{{ formatTime(row.updated_at) }}</template></el-table-column>
    </el-table>

    <el-dialog v-model="dialog" :title="t('新建扫描任务')" width="520px">
      <el-form :model="form" label-width="90px">
        <el-form-item :label="t('任务类型')">
          <el-radio-group v-model="form.kind">
            <el-radio value="discovery">{{ t('资产发现') }}</el-radio>
            <el-radio value="vuln">{{ t('漏洞检测') }}</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="t('探针 ID')" required>
          <el-input v-model="form.probe_id" :placeholder="t('如 seg-a，与探针启动参数 -id 一致')" />
        </el-form-item>
        <el-form-item :label="t('扫描目标')" required>
          <el-input v-model="form.targets" type="textarea" :rows="4" :placeholder="t('每行一个：10.1.0.5、10.1.0.0/24、10.1.1.10-50；单任务最大 /16')" />
        </el-form-item>
        <el-form-item :label="t('端口')">
          <el-input v-model="form.ports" :placeholder="t('逗号分隔，留空使用内置常见高危端口')" />
        </el-form-item>
        <el-form-item v-if="form.kind === 'vuln'" :label="t('弱口令')">
          <el-switch v-model="form.weak_password" />
          <span class="hint">{{ t('尝试少量常见口令（SSH / FTP / Redis）') }}</span>
        </el-form-item>
        <el-alert v-if="form.weak_password" type="warning" :closable="false" show-icon style="margin: -6px 0 16px"
          :title="t('会产生真实的登录失败记录，可能触发账号锁定策略或其他安全设备告警，请先与系统负责人确认。')" />
        <el-form-item :label="t('基线扫描')">
          <el-switch v-model="form.baseline" />
          <span class="hint">{{ t('首次扫描新网段时开启：只建立资产台账，不产生告警') }}</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="submit">{{ t('创建') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const statusMap = {
  pending: { label: t('等待领取'), type: 'info' },
  running: { label: t('执行中'), type: 'warning' },
  done: { label: t('完成'), type: 'success' },
  failed: { label: t('失败'), type: 'danger' },
}

const tasks = ref([])
const loading = ref(false)
const dialog = ref(false)
const submitting = ref(false)
const form = reactive({ kind: 'discovery', probe_id: '', targets: '', ports: '', baseline: false, weak_password: false })

async function load() {
  loading.value = true
  try {
    tasks.value = await api.tasks()
  } finally {
    loading.value = false
  }
}

function openDialog() {
  Object.assign(form, { kind: 'discovery', probe_id: '', targets: '', ports: '', baseline: false, weak_password: false })
  dialog.value = true
}

async function submit() {
  const targets = form.targets.split(/[\s,]+/).filter(Boolean)
  const ports = form.ports.split(/[\s,]+/).filter(Boolean).map(Number)
  if (!form.probe_id.trim() || !targets.length) {
    ElMessage.error(t('请填写探针 ID 和扫描目标'))
    return
  }
  if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
    ElMessage.error(t('端口必须是 1-65535 的整数'))
    return
  }
  submitting.value = true
  try {
    await api.createTask({
      probe_id: form.probe_id.trim(),
      targets,
      ports,
      baseline: form.baseline,
      kind: form.kind,
      weak_password: form.kind === 'vuln' && form.weak_password,
    })
    ElMessage.success(t('任务已创建，等待探针领取'))
    dialog.value = false
    load()
  } finally {
    submitting.value = false
  }
}

// 有未结束的任务时自动刷新状态。
const timer = setInterval(() => {
  if (tasks.value.some((t) => t.status === 'pending' || t.status === 'running')) {
    api.tasks().then((t) => (tasks.value = t)).catch(() => {})
  }
}, 5000)

onMounted(load)
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.hint { margin-left: 12px; color: #909399; font-size: 12px; }
.tag-gap { margin-left: 4px; }
</style>
