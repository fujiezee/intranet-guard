<template>
  <router-view v-if="route.meta.public" />
  <el-container v-else class="layout">
    <el-aside width="200px" class="aside">
      <div class="logo">{{ t('内网防护系统') }}</div>
      <el-menu :default-active="route.path" router background-color="#1f2d3d" text-color="#bfcbd9" active-text-color="#409eff">
        <el-menu-item index="/">{{ t('总览') }}</el-menu-item>
        <el-menu-item index="/assets">{{ t('资产') }}</el-menu-item>
        <el-menu-item index="/incidents">{{ t('事件') }}</el-menu-item>
        <el-menu-item index="/alerts">{{ t('告警') }}</el-menu-item>
        <el-menu-item index="/vulns">{{ t('漏洞') }}</el-menu-item>
        <el-menu-item index="/ids">{{ t('流量检测') }}</el-menu-item>
        <el-menu-item index="/hosts">{{ t('主机审计') }}</el-menu-item>
        <el-menu-item index="/response">{{ t('处置') }}</el-menu-item>
        <el-menu-item index="/intel">{{ t('威胁情报') }}</el-menu-item>
        <el-menu-item index="/honeypot">{{ t('蜜罐') }}</el-menu-item>
        <el-menu-item index="/detection">{{ t('检测验证') }}</el-menu-item>
        <el-menu-item index="/tasks">{{ t('扫描任务') }}</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/nodes">{{ t('节点管理') }}</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/users">{{ t('用户管理') }}</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/settings">{{ t('推送与审计') }}</el-menu-item>
        <el-menu-item index="/help">{{ t('使用帮助') }}</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <span v-if="ver" class="version">
          {{ t('当前 {p0}', { p0: currentVersion }) }}
          <el-tag v-if="ver.server.update_available" size="small" type="warning" effect="dark" class="update" @click="updateOpen = true">
            {{ t('新版本 v{p0}', { p0: ver.server.latest }) }}
          </el-tag>
          <span v-else :title="ver.server.check_error">· {{ latestVersion }}</span>
        </span>
        <!-- 跳到使用指南中当前页面对应的章节（章节锚点与路由名称一致） -->
        <router-link v-if="route.name !== 'help'" class="help-link" :to="{ path: '/help', hash: `#${route.name}` }">{{ t('帮助') }}</router-link>
        <el-button class="lang" size="small" link @click="setLang(lang === 'en' ? 'zh' : 'en')">{{ lang === 'en' ? '中文' : 'English' }}</el-button>
        <el-dropdown @command="onCommand">
          <span class="user">
            {{ auth.user?.username }}
            <el-tag size="small" :type="auth.isAdmin ? 'danger' : 'info'">{{ auth.isAdmin ? t('管理员') : t('只读') }}</el-tag>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">{{ t('修改密码') }}</el-dropdown-item>
              <el-dropdown-item command="logout" divided>{{ t('退出登录') }}</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>

    <el-dialog v-model="pwDialog" :title="t('修改密码')" width="400px">
      <el-form :model="pwForm" label-width="80px">
        <el-form-item :label="t('原密码')"><el-input v-model="pwForm.old" type="password" show-password /></el-form-item>
        <el-form-item :label="t('新密码')"><el-input v-model="pwForm.new" type="password" show-password :placeholder="t('至少 10 位')" /></el-form-item>
        <el-form-item :label="t('确认密码')"><el-input v-model="pwForm.confirm" type="password" show-password /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwDialog = false">{{ t('取消') }}</el-button>
        <el-button type="primary" @click="changePassword">{{ t('确定') }}</el-button>
      </template>
    </el-dialog>
    <el-dialog v-if="ver" v-model="updateOpen" :title="t('新版本 v{p0}', { p0: ver.server.latest })" width="680px">
      <p>{{ t('当前管理中心版本 v{p0}', { p0: ver.server.current }) }}<span v-if="ver.server.published_at">{{ t('，新版本发布于 {p0}', { p0: formatTime(ver.server.published_at) }) }}</span>。</p>
      <pre v-if="ver.server.release_notes" class="notes">{{ ver.server.release_notes }}</pre>
      <h4>{{ t('升级步骤') }}</h4>
      <ol class="steps">
        <li>{{ t('从') }}<a :href="ver.server.release_url" target="_blank" rel="noopener">{{ t('发布页') }}</a>{{ t('下载与管理中心架构对应的安装包（safe-版本-linux-amd64 / arm64.tar.gz）。') }}</li>
        <li>{{ t('拷到管理中心服务器，解压后执行') }} <code>sudo ./install.sh</code>{{ t('：自动升级，数据和配置保留（升级前会自动备份）。') }}</li>
        <li>{{ t('高可用部署时逐台升级各实例。') }}</li>
        <li>{{ t('升级后在「主机审计 → Agent 升级」把节点升级到新版本（可选择自动升级）。') }}</li>
      </ol>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { t, lang, setLang } from './i18n'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from './api'
import { auth, clearSession } from './auth'
import { formatTime } from './format'

const route = useRoute()
const router = useRouter()
const pwDialog = ref(false)
const pwForm = reactive({ old: '', new: '', confirm: '' })
const ver = ref(null)
const updateOpen = ref(false)
let verTimer = null

// 开发构建的版本号是 dev，不加 v 前缀
const currentVersion = computed(() => {
  const v = ver.value.server.current
  return /^\d/.test(v) ? `v${v}` : v
})
const latestVersion = computed(() => {
  const s = ver.value.server
  if (s.latest) return t('最新 v{p0}', { p0: s.latest })
  if (s.disabled) return t('最新：未启用检查')
  if (s.check_error) return t('最新：检查失败')
  return s.checked_at ? t('最新：暂无发布') : t('最新：检查中')
})

async function loadVersion() {
  ver.value = await api.version().catch(() => ver.value)
}

// 登录页没有会话，登录后才加载；管理中心启动后稍等才完成第一次检查，所以定时刷新
watch(() => auth.token, (token) => {
  clearInterval(verTimer)
  ver.value = null
  if (!token) return
  loadVersion()
  verTimer = setInterval(loadVersion, 60000)
}, { immediate: true })

async function onCommand(cmd) {
  if (cmd === 'password') {
    Object.assign(pwForm, { old: '', new: '', confirm: '' })
    pwDialog.value = true
    return
  }
  await api.logout().catch(() => {})
  clearSession()
  router.push({ name: 'login' })
}

async function changePassword() {
  if (pwForm.new !== pwForm.confirm) {
    ElMessage.error(t('两次输入的新密码不一致'))
    return
  }
  await api.changePassword(pwForm.old, pwForm.new)
  // 后端改密码后会让所有会话失效，需要重新登录。
  clearSession()
  pwDialog.value = false
  ElMessage.success(t('密码已修改，请重新登录'))
  router.push({ name: 'login' })
}
</script>

<style scoped>
.version { display: flex; align-items: center; gap: 6px; margin-right: 16px; color: #909399; font-size: 13px; }
.update { cursor: pointer; }
.notes { max-height: 260px; overflow: auto; padding: 8px 12px; background: #f5f7fa; border-radius: 3px; font-size: 13px; white-space: pre-wrap; }
.help-link { margin-right: 16px; color: #409eff; font-size: 14px; text-decoration: none; }
.layout { height: 100%; }
.aside { background: #1f2d3d; }
.aside .el-menu { border-right: none; }
.logo { color: #fff; font-size: 16px; font-weight: 600; height: 60px; line-height: 60px; text-align: center; }
.header { background: #fff; display: flex; align-items: center; justify-content: flex-end; border-bottom: 1px solid #e4e7ed; }
.user { cursor: pointer; display: flex; align-items: center; gap: 8px; outline: none; }
</style>
