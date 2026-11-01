<template>
  <div>
    <div class="page-header">
      <h2>{{ t('安全验证') }}</h2>
      <div class="tools">
        <el-button @click="load">{{ t('刷新') }}</el-button>
        <el-button v-if="auth.isAdmin" type="primary" :disabled="scopes.length === 0" @click="openRun">{{ t('新建验证') }}</el-button>
      </div>
    </div>
    <p class="hint">{{ t('主动检查自己的资产：发现漏洞和弱口令。只能针对下面登记的授权范围，全程写入审计日志。') }}</p>

    <el-card shadow="never" class="card">
      <template #header>
        <div class="card-header">
          {{ t('授权范围') }}
          <el-button v-if="auth.isAdmin" size="small" @click="scopeDialog = true">{{ t('添加范围') }}</el-button>
        </div>
      </template>
      <el-table :data="scopes" size="small" :empty-text="t('还没有授权范围：添加之后才能发起验证')">
        <el-table-column :label="t('网段')" width="200"><template #default="{ row }"><span class="mono">{{ row.cidr }}</span></template></el-table-column>
        <el-table-column prop="note" :label="t('授权说明')" min-width="240" />
        <el-table-column prop="created_by" :label="t('添加人')" width="120" />
        <el-table-column :label="t('添加时间')" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
        <el-table-column v-if="auth.isAdmin" width="80">
          <template #default="{ row }"><el-button link type="danger" @click="removeScope(row)">{{ t('删除') }}</el-button></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card v-if="coverage" shadow="never" class="card">
      <template #header>
        <div class="card-header">
          {{ t('检测覆盖') }}
          <span class="hint">{{ t('最近 {p0} 天攻击模拟自检的结果。通过表示模拟动作能触发告警，不代表能发现真实攻击。', { p0: coverage.window_days }) }}</span>
        </div>
      </template>
      <div class="summary">
        <el-tag type="success">{{ t('已验证 {p0}', { p0: coverage.summary.verified || 0 }) }}</el-tag>
        <el-tag type="danger">{{ t('未通过 {p0}', { p0: coverage.summary.failed || 0 }) }}</el-tag>
        <el-tag type="warning">{{ t('待自检 {p0}', { p0: coverage.summary.not_run || 0 }) }}</el-tag>
        <el-tag type="info">{{ t('无自检场景 {p0}', { p0: coverage.summary.no_scenario || 0 }) }}</el-tag>
        <span v-if="coverage.avg_latency_ms" class="hint">{{ t('平均检出耗时 {p0} 秒', { p0: (coverage.avg_latency_ms / 1000).toFixed(1) }) }}</span>
      </div>
      <el-alert v-if="blind.length" type="error" :closable="false" show-icon class="card"
        :title="t('没有检测规则的 ATT&CK 战术：{p0}', { p0: blind.join('、') })" />
      <el-table :data="coverage.rules" size="small" max-height="360">
        <el-table-column prop="name" :label="t('规则')" min-width="160" />
        <el-table-column prop="tactic" :label="t('ATT&CK 战术')" min-width="150" />
        <el-table-column :label="t('结果')" width="110">
          <template #default="{ row }"><el-tag size="small" :type="coverageMap[row.state].type">{{ coverageMap[row.state].label }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="t('最近自检')" width="170"><template #default="{ row }">{{ row.last_run ? formatTime(row.last_run) : '-' }}</template></el-table-column>
      </el-table>
    </el-card>

    <el-table :data="runs" v-loading="loading" stripe :empty-text="t('还没有验证任务')">
      <el-table-column prop="name" :label="t('名称')" min-width="160" />
      <el-table-column :label="t('目标')" min-width="180"><template #default="{ row }"><span class="mono">{{ row.targets.join(', ') }}</span></template></el-table-column>
      <el-table-column prop="probe_id" :label="t('探针')" width="100" />
      <el-table-column :label="t('检查项')" width="170">
        <template #default="{ row }">
          <el-tag size="small" type="warning">{{ t('漏洞') }}</el-tag>
          <el-tag v-if="row.weak_password" size="small" type="danger" class="tag-gap">{{ t('弱口令') }}</el-tag>
          <el-tag v-if="row.nuclei" size="small" type="danger" class="tag-gap">Nuclei</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('状态')" width="110">
        <template #default="{ row }">
          <el-tooltip :disabled="!row.error" :content="row.error">
            <el-tag size="small" :type="statusMap[row.status]?.type">{{ statusMap[row.status]?.label }}</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column :label="t('发起 / 批准')" width="170"><template #default="{ row }">{{ row.created_by }} / {{ row.approved_by || '-' }}</template></el-table-column>
      <el-table-column :label="t('创建时间')" width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column width="110">
        <template #default="{ row }">
          <el-button v-if="auth.isAdmin && row.status === 'awaiting_approval'" link type="primary" @click="approve(row)">{{ t('批准') }}</el-button>
          <el-button v-if="row.started_at" link type="primary" @click="openReport(row)">{{ t('报告') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="scopeDialog" :title="t('添加授权范围')" width="480px">
      <el-form :model="scopeForm" label-width="90px">
        <el-form-item :label="t('网段')" required><el-input v-model="scopeForm.cidr" placeholder="10.1.0.0/24" /></el-form-item>
        <el-form-item :label="t('授权说明')" required>
          <el-input v-model="scopeForm.note" :placeholder="t('例如：测试环境，已获系统负责人同意')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="scopeDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="addScope">{{ t('添加') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="runDialog" :title="t('新建验证')" width="520px">
      <el-form :model="form" label-width="90px">
        <el-form-item :label="t('名称')" required><el-input v-model="form.name" :placeholder="t('例如：测试网段月度检查')" /></el-form-item>
        <el-form-item :label="t('探针 ID')" required><el-input v-model="form.probe_id" :placeholder="t('如 seg-a，与探针启动参数 -id 一致')" /></el-form-item>
        <el-form-item :label="t('验证目标')" required>
          <el-input v-model="form.targets" type="textarea" :rows="3" :placeholder="t('每行一个：10.1.0.5、10.1.0.0/24、10.1.1.10-50；必须在授权范围内')" />
        </el-form-item>
        <el-form-item :label="t('端口')"><el-input v-model="form.ports" :placeholder="t('逗号分隔，留空使用内置常见高危端口')" /></el-form-item>
        <el-form-item :label="t('弱口令')">
          <el-switch v-model="form.weak_password" />
          <span class="hint inline">{{ t('尝试少量常见口令（SSH / FTP / Redis）') }}</span>
        </el-form-item>
        <el-form-item label="Nuclei">
          <el-switch v-model="form.nuclei" />
          <span class="hint inline">{{ t('运行非破坏性模板，探针上需要已安装 nuclei') }}</span>
        </el-form-item>
        <el-alert v-if="form.weak_password || form.nuclei" type="warning" :closable="false" show-icon
          :title="t('会向目标发送真实的探测和登录请求，可能产生登录失败、账号锁定或其他安全设备告警，请先与系统负责人确认。创建后需要批准才会执行：有多位管理员时由另一位批准。')" />
      </el-form>
      <template #footer>
        <el-button @click="runDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="createRun">{{ form.weak_password || form.nuclei ? t('提交审批') : t('开始验证') }}</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="reportOpen" :title="t('验证报告')" size="720px">
      <template v-if="report">
        <h3>{{ report.run.name }}</h3>
        <el-alert v-if="report.run.status !== 'done'" type="warning" :closable="false" show-icon class="card"
          :title="report.run.status === 'failed' ? t('验证失败：{p0}。下面的结果不完整。', { p0: report.run.error || '-' }) : t('验证尚未完成，下面的结果不完整。')" />
        <div class="summary">
          <el-tag type="danger">{{ t('高危 {p0}', { p0: report.counts.high || 0 }) }}</el-tag>
          <el-tag type="warning">{{ t('中危 {p0}', { p0: report.counts.medium || 0 }) }}</el-tag>
          <el-tag type="info">{{ t('低危 {p0}', { p0: report.counts.low || 0 }) }}</el-tag>
          <el-tag type="success">{{ t('已修复 {p0}', { p0: report.fixed.length }) }}</el-tag>
        </div>
        <el-table :data="report.findings" size="small" :empty-text="t('本次检查项未发现问题')">
          <el-table-column :label="t('地址')" width="170"><template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.port }}</span></template></el-table-column>
          <el-table-column prop="title" :label="t('问题')" min-width="200" />
          <el-table-column prop="severity" :label="t('等级')" width="80" />
          <el-table-column prop="detail" :label="t('详情')" min-width="200" />
        </el-table>
        <p class="hint">{{ t('未发现问题只说明本次检查项通过，不代表资产是安全的。业务逻辑漏洞和组合利用不在自动检查范围内。') }}</p>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const statusMap = {
  awaiting_approval: { label: t('待批准'), type: 'warning' },
  running: { label: t('执行中'), type: '' },
  done: { label: t('已完成'), type: 'success' },
  failed: { label: t('失败'), type: 'danger' },
  expired: { label: t('已失效'), type: 'info' },
}
const coverageMap = {
  verified: { label: t('已验证'), type: 'success' },
  failed: { label: t('未通过'), type: 'danger' },
  not_run: { label: t('待自检'), type: 'warning' },
  no_scenario: { label: t('无自检场景'), type: 'info' },
}
const coverage = ref(null)
const blind = computed(() => (coverage.value?.tactics || []).filter((x) => x.rules === 0).map((x) => x.tactic))
const scopes = ref([])
const runs = ref([])
const loading = ref(false)
const scopeDialog = ref(false)
const runDialog = ref(false)
const reportOpen = ref(false)
const report = ref(null)
const scopeForm = reactive({ cidr: '', note: '' })
const form = reactive({ name: '', probe_id: '', targets: '', ports: '', weak_password: false, nuclei: false })

async function load() {
  loading.value = true
  try {
    ;[scopes.value, runs.value, coverage.value] = await Promise.all([api.validationScopes(), api.validationRuns(), api.detectionCoverage()])
  } finally {
    loading.value = false
  }
}

async function addScope() {
  await api.addValidationScope({ cidr: scopeForm.cidr, note: scopeForm.note })
  Object.assign(scopeForm, { cidr: '', note: '' })
  scopeDialog.value = false
  load()
}

async function removeScope(row) {
  await ElMessageBox.confirm(t('删除授权范围 {p0}？之后不能再对其发起验证。', { p0: row.cidr }), t('删除'), { type: 'warning' })
  await api.deleteValidationScope(row.id)
  load()
}

function openRun() {
  Object.assign(form, { name: '', probe_id: '', targets: '', ports: '', weak_password: false, nuclei: false })
  runDialog.value = true
}

async function createRun() {
  const r = await api.createValidationRun({
    name: form.name,
    probe_id: form.probe_id.trim(),
    targets: form.targets.split('\n').map((s) => s.trim()).filter(Boolean),
    ports: form.ports.split(',').map((s) => parseInt(s, 10)).filter(Boolean),
    weak_password: form.weak_password,
    nuclei: form.nuclei,
  })
  ElMessage.success(r.status === 'running' ? t('验证已开始，等待探针领取') : t('已提交，等待批准'))
  runDialog.value = false
  load()
}

async function approve(row) {
  await ElMessageBox.confirm(t('批准后将对 {p0} 发送真实的探测请求，可能产生登录失败记录和安全设备告警。', { p0: row.targets.join(', ') }), t('批准'), { type: 'warning' })
  await api.approveValidationRun(row.id)
  ElMessage.success(t('已批准，等待探针领取'))
  load()
}

async function openReport(row) {
  report.value = await api.validationReport(row.id)
  reportOpen.value = true
}

onMounted(load)
</script>

<style scoped>
.hint { color: #909399; font-size: 12px; line-height: 1.6; }
.hint.inline { margin-left: 8px; }
.card { margin-bottom: 12px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.summary { display: flex; gap: 8px; margin-bottom: 12px; }
.mono { font-family: monospace; }
.tag-gap { margin-left: 4px; }
</style>
