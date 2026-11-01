<template>
  <div>
    <div class="page-header">
      <h2>蜜罐</h2>
      <div class="tools">
        <el-button @click="load">刷新</el-button>
        <el-button v-if="auth.isAdmin" type="primary" @click="edit(null)">为探针配置蜜罐</el-button>
      </div>
    </div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px"
      title="蜜罐运行在探针上，伪装成常见服务。正常业务不会访问它，任何访问都会以高危告警推送——访问来源很可能已失陷。探针自身的扫描不会触发告警。" />

    <el-card shadow="never" header="探针蜜罐">
      <el-table :data="honeypots" size="small" empty-text="还没有配置蜜罐">
        <el-table-column prop="probe_id" label="探针" width="140" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.config.enabled ? 'success' : 'info'">{{ row.config.enabled ? '启用' : '停用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="地址" width="160">
          <template #default="{ row }"><span class="mono">{{ (row.probe_ips || []).filter((ip) => !ip.includes(':')).join(', ') || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="伪装服务" min-width="320">
          <template #default="{ row }">
            <el-tooltip v-for="s in row.config.services" :key="s.port" :content="row.status?.[s.port] || '等待探针上报'">
              <el-tag size="small" class="svc" :type="portType(row, s.port)">{{ serviceLabel(s.type) }} :{{ s.port }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="最近同步" width="170"><template #default="{ row }">{{ formatTime(row.seen_at) || '-' }}</template></el-table-column>
        <el-table-column v-if="auth.isAdmin" label="操作" width="80">
          <template #default="{ row }"><el-button size="small" link type="primary" @click="edit(row)">编辑</el-button></template>
        </el-table-column>
      </el-table>
      <p class="hint">端口为红色表示监听失败（多为端口已被占用），鼠标悬停查看原因。</p>
    </el-card>

    <el-card shadow="never" header="访问记录" style="margin-top: 16px">
      <el-table :data="events" size="small" stripe empty-text="暂无访问">
        <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatTime(row.time) }}</template></el-table-column>
        <el-table-column label="来源" width="160">
          <template #default="{ row }"><span class="mono">{{ row.src_ip }}</span></template>
        </el-table-column>
        <el-table-column label="蜜罐" width="190">
          <template #default="{ row }">{{ row.probe_id }} · {{ serviceLabel(row.service) }} :{{ row.port }}</template>
        </el-table-column>
        <el-table-column label="尝试凭据" width="170">
          <template #default="{ row }"><span class="mono">{{ [row.username, row.password].filter(Boolean).join(' / ') }}</span></template>
        </el-table-column>
        <el-table-column label="详情" min-width="280">
          <template #default="{ row }">
            <el-tag v-if="row.simulation_id" size="small" type="success" style="margin-right: 4px">自检</el-tag>{{ row.detail }}
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialog" title="配置蜜罐" width="600px">
      <el-form label-width="90px">
        <el-form-item label="探针 ID">
          <el-select v-model="form.probe_id" filterable allow-create placeholder="选择或输入探针 ID" style="width: 100%" :disabled="editing">
            <el-option v-for="p in probes" :key="p" :label="p" :value="p" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
        <el-form-item label="伪装服务">
          <div class="svc-list">
            <div v-for="(s, i) in form.services" :key="i" class="svc-row">
              <el-select v-model="s.type" style="width: 150px">
                <el-option v-for="(label, value) in types" :key="value" :label="label" :value="value" />
              </el-select>
              <el-input-number v-model="s.port" :min="1" :max="65535" controls-position="right" />
              <el-button link type="danger" @click="form.services.splice(i, 1)">移除</el-button>
            </div>
            <div>
              <el-button size="small" @click="form.services.push({ type: 'tcp', port: 10000 })">添加</el-button>
              <el-button size="small" link @click="form.services = presets()">恢复推荐配置</el-button>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="忽略来源">
          <el-input v-model="form.ignore" type="textarea" :rows="2" placeholder="每行一个 IP 或网段，如内部漏洞扫描器 10.1.0.50" />
        </el-form-item>
      </el-form>
      <p class="hint">端口不能与探针机器上已有的服务冲突（例如 SSH 的 22）。端口低于 1024 需要探针以 root 运行（一键安装默认如此）。</p>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const types = { ssh: 'SSH', ftp: 'FTP', telnet: 'Telnet', mysql: 'MySQL', redis: 'Redis', http: 'HTTP 管理后台', tcp: '通用 TCP（RDP/SMB 等）' }
const serviceLabel = (t) => types[t]?.split('（')[0] || t
const presets = () => [
  { type: 'ssh', port: 2222 },
  { type: 'ftp', port: 21 },
  { type: 'telnet', port: 23 },
  { type: 'mysql', port: 3306 },
  { type: 'redis', port: 6379 },
  { type: 'http', port: 8088 },
  { type: 'tcp', port: 3389 },
  { type: 'tcp', port: 445 },
]

const honeypots = ref([])
const events = ref([])
const nodes = ref([])
const dialog = ref(false)
const editing = ref(false)
const form = reactive({ probe_id: '', enabled: true, services: [], ignore: '' })
const probes = computed(() => nodes.value.filter((n) => n.kind === 'probe' && n.status === 'active').map((n) => n.id))

function portType(row, port) {
  const st = row.status?.[port]
  if (!row.config.enabled) return 'info'
  if (st === 'listening') return 'success'
  return st ? 'danger' : 'warning'
}

async function load() {
  const [h, e] = await Promise.all([api.honeypots(), api.honeypotEvents()])
  honeypots.value = h
  events.value = e
  if (auth.isAdmin) nodes.value = await api.nodes().catch(() => [])
}

function edit(row) {
  editing.value = !!row
  Object.assign(form, row
    ? { probe_id: row.probe_id, enabled: row.config.enabled, services: row.config.services.map((s) => ({ ...s })), ignore: row.config.ignore_sources.join('\n') }
    : { probe_id: probes.value[0] || '', enabled: true, services: presets(), ignore: '' })
  dialog.value = true
}

async function save() {
  if (!form.probe_id) {
    ElMessage.error('请选择探针')
    return
  }
  await api.setHoneypot(form.probe_id, {
    enabled: form.enabled,
    services: form.services,
    ignore_sources: form.ignore.split(/\s+/).filter(Boolean),
  })
  ElMessage.success('已保存，探针将在 15 秒内生效')
  dialog.value = false
  load()
}

onMounted(load)
</script>

<style scoped>
.tools { display: flex; gap: 8px; }
.svc { margin: 2px 4px 2px 0; }
.svc-list { display: flex; flex-direction: column; gap: 6px; width: 100%; }
.svc-row { display: flex; gap: 8px; align-items: center; }
.hint { color: #909399; font-size: 12px; margin: 8px 0 0; }
</style>
