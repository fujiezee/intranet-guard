<template>
  <div>
    <div class="page-header"><h2>推送与审计</h2></div>
    <el-tabs v-model="tab" @tab-change="onTab">
      <el-tab-pane label="告警推送" name="channels">
        <div class="bar">
          <span class="hint">新告警每 10 秒推送一次，同一批告警合并为一条消息。</span>
          <el-button type="primary" @click="openDialog">添加渠道</el-button>
        </div>
        <el-table :data="channels" size="small" stripe empty-text="还没有推送渠道，告警只能在控制台查看">
          <el-table-column prop="name" label="名称" width="140" />
          <el-table-column label="类型" width="100"><template #default="{ row }">{{ typeLabels[row.type] }}</template></el-table-column>
          <el-table-column label="地址" min-width="240"><template #default="{ row }"><span class="mono sub">{{ row.url }}</span></template></el-table-column>
          <el-table-column label="推送级别" width="100"><template #default="{ row }">{{ sevLabels[row.min_severity] }}及以上</template></el-table-column>
          <el-table-column label="最近状态" min-width="200">
            <template #default="{ row }">
              <span v-if="row.last_error" class="err">失败：{{ row.last_error }}</span>
              <span v-else-if="row.last_sent_at" class="ok">{{ formatTime(row.last_sent_at) }} 发送成功</span>
              <span v-else class="sub">尚未发送</span>
            </template>
          </el-table-column>
          <el-table-column label="启用" width="70">
            <template #default="{ row }"><el-switch :model-value="row.enabled" size="small" @change="(v) => toggle(row, v)" /></template>
          </el-table-column>
          <el-table-column label="操作" width="120">
            <template #default="{ row }">
              <el-button size="small" link type="primary" :loading="testing === row.id" @click="test(row)">测试</el-button>
              <el-button size="small" link type="danger" @click="remove(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="操作审计" name="audit">
        <div class="bar">
          <div class="filters">
            <el-input v-model="auditFilter.username" placeholder="用户名" clearable style="width: 140px" @change="loadAudit" />
            <el-select v-model="auditFilter.action" placeholder="全部操作" clearable filterable style="width: 200px" @change="loadAudit">
              <el-option v-for="(label, value) in actionLabels" :key="value" :label="label" :value="value" />
            </el-select>
          </div>
          <el-button @click="loadAudit">刷新</el-button>
        </div>
        <el-table :data="audit" size="small" stripe>
          <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.time) }}</template></el-table-column>
          <el-table-column prop="username" label="用户" width="110" />
          <el-table-column label="操作" width="150"><template #default="{ row }">{{ actionLabels[row.action] || row.action }}</template></el-table-column>
          <el-table-column label="结果" width="70">
            <template #default="{ row }"><el-tag size="small" :type="row.success ? 'success' : 'danger'">{{ row.success ? '成功' : '失败' }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="target" label="对象" width="160" />
          <el-table-column label="详情" min-width="240"><template #default="{ row }"><span class="sub">{{ row.detail }}</span></template></el-table-column>
          <el-table-column label="来源 IP" width="130"><template #default="{ row }"><span class="mono">{{ row.client_ip }}</span></template></el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="dialog" title="添加推送渠道" width="520px">
      <el-form :model="form" label-width="90px">
        <el-form-item label="名称"><el-input v-model="form.name" placeholder="例如：安全值班群" /></el-form-item>
        <el-form-item label="类型">
          <el-radio-group v-model="form.type">
            <el-radio v-for="(label, value) in typeLabels" :key="value" :value="value">{{ label }}</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="Webhook"><el-input v-model="form.url" :placeholder="urlHints[form.type]" /></el-form-item>
        <el-form-item v-if="form.type === 'dingtalk' || form.type === 'feishu'" label="加签密钥">
          <el-input v-model="form.secret" placeholder="机器人安全设置中的“加签”密钥，未开启可留空" />
        </el-form-item>
        <el-form-item label="推送级别">
          <el-radio-group v-model="form.min_severity">
            <el-radio value="high">仅高危</el-radio>
            <el-radio value="medium">中危及以上</el-radio>
            <el-radio value="low">全部</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" @click="submit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { formatTime } from '../format'

const typeLabels = { wecom: '企业微信', dingtalk: '钉钉', feishu: '飞书', webhook: '通用 Webhook' }
const sevLabels = { high: '高危', medium: '中危', low: '低危' }
const urlHints = {
  wecom: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…',
  dingtalk: 'https://oapi.dingtalk.com/robot/send?access_token=…',
  feishu: 'https://open.feishu.cn/open-apis/bot/v2/hook/…',
  webhook: 'https://your-system.example.com/alerts（POST JSON）',
}
const actionLabels = {
  'auth.login': '登录',
  'auth.logout': '退出',
  'user.create': '创建用户',
  'user.delete': '删除用户',
  'user.password': '修改密码',
  'task.create': '下发扫描任务',
  'alert.ack': '确认告警',
  'vuln.status': '修改漏洞状态',
  'ids.suppression.create': '添加 IDS 抑制',
  'ids.suppression.delete': '删除 IDS 抑制',
  'node.revoke': '吊销节点',
  'enroll_token.create': '生成注册令牌',
  'enroll_token.delete': '删除注册令牌',
  'notify_channel.create': '添加推送渠道',
  'notify_channel.delete': '删除推送渠道',
  'notify_channel.enabled': '启停推送渠道',
}

const tab = ref('channels')
const channels = ref([])
const audit = ref([])
const auditFilter = reactive({ username: '', action: '' })
const dialog = ref(false)
const testing = ref(0)
const form = reactive({ name: '', type: 'wecom', url: '', secret: '', min_severity: 'medium' })

async function loadChannels() {
  channels.value = await api.channels()
}

async function loadAudit() {
  audit.value = await api.audit(Object.fromEntries(Object.entries(auditFilter).filter(([, v]) => v)))
}

function onTab(name) {
  name === 'audit' ? loadAudit() : loadChannels()
}

function openDialog() {
  Object.assign(form, { name: '', type: 'wecom', url: '', secret: '', min_severity: 'medium' })
  dialog.value = true
}

async function submit() {
  await api.createChannel({ ...form })
  ElMessage.success('已添加，建议点“测试”确认能收到消息')
  dialog.value = false
  loadChannels()
}

async function toggle(row, enabled) {
  await api.setChannelEnabled(row.id, enabled)
  loadChannels()
}

async function test(row) {
  testing.value = row.id
  try {
    await api.testChannel(row.id)
    ElMessage.success('测试消息已发送，请在群里确认')
  } catch {
    // 错误原因已由 api 层提示
  } finally {
    testing.value = 0
    loadChannels()
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`删除推送渠道“${row.name}”？`, '删除', { type: 'warning' })
  } catch {
    return
  }
  await api.deleteChannel(row.id)
  loadChannels()
}

onMounted(loadChannels)
</script>

<style scoped>
.bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.filters { display: flex; gap: 8px; }
.hint, .sub { color: #909399; font-size: 12px; }
.err { color: #f56c6c; font-size: 12px; }
.ok { color: #67c23a; font-size: 12px; }
</style>
