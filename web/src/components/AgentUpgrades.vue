<template>
  <el-drawer :model-value="modelValue" :title="t('Agent 升级')" size="820px" @update:model-value="(v) => emit('update:modelValue', v)" @open="load">
    <el-alert v-if="!data.latest.version" type="warning" :closable="false" show-icon
      :title="t('管理中心没有可分发的 Agent 版本：请用 make release 生成的安装包部署或升级管理中心（安装包中含各平台 Agent 程序和版本清单）。')" />
    <template v-else>
      <div class="latest">
        {{ t('管理中心提供的版本：') }}<b>{{ data.latest.version }}</b>
        <span class="sub">（{{ data.latest.files.join('、') }}）</span>
      </div>
      <div class="summary">
        <el-tag type="success">{{ t('已是最新 {p0}', { p0: count.current }) }}</el-tag>
        <el-tag type="warning">{{ t('可升级 {p0}', { p0: count.outdated }) }}</el-tag>
        <el-tag>{{ t('升级中 {p0}', { p0: count.upgrading }) }}</el-tag>
        <el-tag type="danger">{{ t('失败 {p0}', { p0: count.failed }) }}</el-tag>
      </div>

      <el-card shadow="never" class="policy">
        <template #header>{{ t('升级策略') }}</template>
        <el-alert v-if="data.policy.paused" type="error" :closable="false" show-icon style="margin-bottom: 12px" :title="data.policy.paused_reason || t('自动升级已暂停')">
          <el-button v-if="auth.isAdmin" size="small" type="primary" style="margin-top: 6px" @click="savePolicy({ paused: false })">{{ t('恢复自动升级') }}</el-button>
        </el-alert>
        <el-form label-width="110px" :disabled="!auth.isAdmin">
          <el-form-item :label="t('方式')">
            <el-radio-group v-model="form.mode">
              <el-radio value="manual">{{ t('手动：只升级下面选中的主机') }}</el-radio>
              <el-radio value="auto">{{ t('自动：旧版本主机自动升级') }}</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item :label="t('每批最多')">
            <el-input-number v-model="form.max_concurrent" :min="1" :max="1000" /> <span class="hint">{{ t('台同时升级，完成一批再开始下一批') }}</span>
          </el-form-item>
          <el-form-item :label="t('失败暂停')">
            <el-input-number v-model="form.max_failures" :min="1" :max="100" /> <span class="hint">{{ t('台升级失败后暂停自动升级，避免问题版本扩散') }}</span>
          </el-form-item>
          <el-form-item v-if="auth.isAdmin">
            <el-button type="primary" @click="savePolicy({})">{{ t('保存策略') }}</el-button>
          </el-form-item>
        </el-form>
        <p class="hint">
          {{ t('升级过程：Agent 下载新版本并校验 → 新版本先自检（能启动、能通过管理中心认证）→ 替换并重启。自检不通过不会替换；Linux / Kubernetes 上新版本启动后反复退出会自动换回旧版本。开发构建（版本号不是 x.y.z）不会被自动升级。') }}
        </p>
      </el-card>

      <div class="toolbar">
        <el-checkbox v-model="onlyOutdated">{{ t('只看可升级 / 失败的主机') }}</el-checkbox>
        <el-button v-if="auth.isAdmin" type="primary" :disabled="selected.length === 0" @click="queue(selected.map((a) => a.id))">{{ t('升级选中的 {p0} 台', { p0: selected.length }) }}</el-button>
      </div>
      <el-table :data="rows" size="small" max-height="460" @selection-change="(v) => (selected = v)">
        <el-table-column v-if="auth.isAdmin" type="selection" width="40" :selectable="(r) => r.outdated && r.upgrade?.state !== 'upgrading'" />
        <el-table-column :label="t('主机')" min-width="150"><template #default="{ row }">{{ row.hostname || row.id }}</template></el-table-column>
        <el-table-column prop="os" :label="t('系统')" width="110" />
        <el-table-column :label="t('版本')" width="110">
          <template #default="{ row }">
            {{ row.version }}
            <el-tag v-if="row.outdated" size="small" type="warning">{{ t('旧') }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('状态')" width="70">
          <template #default="{ row }">{{ { online: t('在线'), offline: t('离线'), stopped: t('已停止') }[row.status] || row.status }}</template>
        </el-table-column>
        <el-table-column :label="t('升级')" min-width="230">
          <template #default="{ row }">
            <template v-if="row.upgrade">
              <el-tag size="small" :type="stateMap[row.upgrade.state]?.type">{{ stateMap[row.upgrade.state]?.label }}</el-tag>
              <span class="sub"> → {{ row.upgrade.target }} · {{ formatTime(row.upgrade.updated_at) }}</span>
              <div v-if="row.upgrade.detail" class="detail">{{ row.upgrade.detail }}</div>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </template>
  </el-drawer>
</template>

<script setup>
import { t } from '../i18n'
import { computed, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

defineProps({ modelValue: Boolean })
const emit = defineEmits(['update:modelValue'])

const stateMap = {
  queued: { label: t('等待上报'), type: 'info' },
  upgrading: { label: t('升级中'), type: '' },
  succeeded: { label: t('成功'), type: 'success' },
  failed: { label: t('失败'), type: 'danger' },
}
const data = ref({ latest: { version: '', files: [] }, policy: {}, agents: [] })
const form = reactive({ mode: 'manual', max_concurrent: 20, max_failures: 3 })
const selected = ref([])
const onlyOutdated = ref(true)
let timer = null

const count = computed(() => {
  const c = { current: 0, outdated: 0, upgrading: 0, failed: 0 }
  for (const a of data.value.agents) {
    if (a.upgrade?.state === 'upgrading' || a.upgrade?.state === 'queued') c.upgrading++
    else if (a.upgrade?.state === 'failed' && a.outdated) c.failed++
    else if (a.outdated) c.outdated++
    else c.current++
  }
  return c
})
const rows = computed(() =>
  onlyOutdated.value ? data.value.agents.filter((a) => a.outdated || a.upgrade?.state === 'failed' || a.upgrade?.state === 'upgrading') : data.value.agents,
)

async function load() {
  data.value = await api.upgrades()
  Object.assign(form, { mode: data.value.policy.mode, max_concurrent: data.value.policy.max_concurrent, max_failures: data.value.policy.max_failures })
  // 有主机在升级时每 5 秒刷新进度
  clearTimeout(timer)
  if (count.value.upgrading > 0) timer = setTimeout(load, 5000)
}

async function savePolicy(extra) {
  await api.setUpgradePolicy({ ...form, paused: false, ...extra })
  ElMessage.success(t('已保存'))
  load()
}

async function queue(ids) {
  const { queued } = await api.queueUpgrades(ids)
  ElMessage.success(t('已安排 {p0} 台主机升级：它们下次上报（通常 30 秒内）时开始', { p0: queued }))
  load()
}
</script>

<style scoped>
.latest { margin-bottom: 8px; }
.summary { display: flex; gap: 8px; margin-bottom: 12px; }
.policy { margin-bottom: 12px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.hint { color: #909399; font-size: 12px; margin-left: 8px; }
p.hint { margin: 0; line-height: 1.6; }
.sub { color: #909399; font-size: 12px; }
.detail { color: #c45656; font-size: 12px; }
</style>
