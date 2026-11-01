<template>
  <div>
    <div class="page-header">
      <h2>{{ t('用户管理') }}</h2>
      <el-button type="primary" @click="openDialog">{{ t('新建用户') }}</el-button>
    </div>
    <el-table :data="users" v-loading="loading" stripe>
      <el-table-column prop="id" label="ID" width="70" />
      <el-table-column prop="username" :label="t('用户名')" />
      <el-table-column :label="t('角色')" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="row.role === 'admin' ? 'danger' : 'info'">{{ row.role === 'admin' ? t('管理员') : t('只读') }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('创建时间')" width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column :label="t('操作')" width="100">
        <template #default="{ row }">
          <el-button v-if="row.id !== auth.user?.id" size="small" type="danger" link @click="remove(row)">{{ t('删除') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="page-header tokens">
      <h3>{{ t('API 令牌（只读）') }}</h3>
      <el-button @click="tokenDialog = true">{{ t('新建令牌') }}</el-button>
    </div>
    <p class="hint">{{ t('用于 MCP 等外部工具查询数据。令牌只能读取，不能执行任何操作。') }}</p>
    <el-table :data="tokens" stripe>
      <el-table-column prop="name" :label="t('名称')" />
      <el-table-column prop="created_by" :label="t('创建人')" width="140" />
      <el-table-column :label="t('创建时间')" width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column :label="t('最近使用')" width="180"><template #default="{ row }">{{ row.last_used_at ? formatTime(row.last_used_at) : '-' }}</template></el-table-column>
      <el-table-column :label="t('操作')" width="100">
        <template #default="{ row }">
          <el-button size="small" type="danger" link @click="revoke(row)">{{ t('吊销') }}</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="tokenDialog" :title="t('新建令牌')" width="420px">
      <el-input v-model="tokenName" :placeholder="t('名称，例如 claude-code')" maxlength="64" />
      <template #footer>
        <el-button @click="tokenDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" :disabled="!tokenName.trim()" @click="createToken">{{ t('创建') }}</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="tokenShown" :title="t('令牌已创建')" width="640px" @closed="newToken = ''">
      <el-alert type="warning" :closable="false" show-icon :title="t('令牌只显示这一次，请立即保存。')" />
      <p>{{ t('把下面的配置加入 MCP 客户端：') }}</p>
      <pre class="config">{{ mcpConfig }}</pre>
    </el-dialog>

    <el-dialog v-model="dialog" :title="t('新建用户')" width="420px">
      <el-form :model="form" label-width="70px">
        <el-form-item :label="t('用户名')"><el-input v-model="form.username" /></el-form-item>
        <el-form-item :label="t('密码')"><el-input v-model="form.password" type="password" show-password :placeholder="t('至少 10 位')" /></el-form-item>
        <el-form-item :label="t('角色')">
          <el-radio-group v-model="form.role">
            <el-radio value="viewer">{{ t('只读') }}</el-radio>
            <el-radio value="admin">{{ t('管理员') }}</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="submit">{{ t('创建') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { t } from '../i18n'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const users = ref([])
const loading = ref(false)
const dialog = ref(false)
const form = reactive({ username: '', password: '', role: 'viewer' })
const tokens = ref([])
const tokenDialog = ref(false)
const tokenShown = ref(false)
const tokenName = ref('')
const newToken = ref('')
const mcpConfig = computed(() => JSON.stringify({
  mcpServers: { 'intranet-guard': { command: 'safe-mcp', env: { SAFE_URL: location.origin, SAFE_API_TOKEN: newToken.value } } },
}, null, 2))

async function loadTokens() {
  tokens.value = await api.apiTokens()
}

async function createToken() {
  const { token } = await api.createAPIToken(tokenName.value.trim())
  newToken.value = token
  tokenName.value = ''
  tokenDialog.value = false
  tokenShown.value = true
  loadTokens()
}

async function revoke(row) {
  try {
    await ElMessageBox.confirm(t('确定吊销令牌 {p0}？使用它的工具会立即失去访问权限。', { p0: row.name }), t('吊销令牌'), { type: 'warning' })
  } catch {
    return // 用户取消
  }
  await api.deleteAPIToken(row.id)
  ElMessage.success(t('已吊销'))
  loadTokens()
}

async function load() {
  loading.value = true
  try {
    users.value = await api.users()
  } finally {
    loading.value = false
  }
}

function openDialog() {
  Object.assign(form, { username: '', password: '', role: 'viewer' })
  dialog.value = true
}

async function submit() {
  await api.createUser({ ...form })
  ElMessage.success(t('用户已创建'))
  dialog.value = false
  load()
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(t('确定删除用户 {p0}？', { p0: row.username }), t('删除用户'), { type: 'warning' })
  } catch {
    return // 用户取消
  }
  await api.deleteUser(row.id)
  ElMessage.success(t('已删除'))
  load()
}

onMounted(() => {
  load()
  loadTokens()
})
</script>

<style scoped>
.tokens { margin-top: 24px; }
.hint { color: #909399; font-size: 13px; }
.config { padding: 8px 12px; background: #f5f7fa; border-radius: 3px; font-size: 12px; overflow: auto; }
</style>
