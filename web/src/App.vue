<template>
  <router-view v-if="route.meta.public" />
  <el-container v-else class="layout">
    <el-aside width="200px" class="aside">
      <div class="logo">内网防护系统</div>
      <el-menu :default-active="route.path" router background-color="#1f2d3d" text-color="#bfcbd9" active-text-color="#409eff">
        <el-menu-item index="/">总览</el-menu-item>
        <el-menu-item index="/assets">资产</el-menu-item>
        <el-menu-item index="/incidents">事件</el-menu-item>
        <el-menu-item index="/alerts">告警</el-menu-item>
        <el-menu-item index="/vulns">漏洞</el-menu-item>
        <el-menu-item index="/ids">流量检测</el-menu-item>
        <el-menu-item index="/hosts">主机审计</el-menu-item>
        <el-menu-item index="/response">处置</el-menu-item>
        <el-menu-item index="/intel">威胁情报</el-menu-item>
        <el-menu-item index="/honeypot">蜜罐</el-menu-item>
        <el-menu-item index="/detection">检测验证</el-menu-item>
        <el-menu-item index="/tasks">扫描任务</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/nodes">节点管理</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/users">用户管理</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/settings">推送与审计</el-menu-item>
        <el-menu-item index="/help">使用帮助</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <!-- 跳到使用指南中当前页面对应的章节（章节锚点与路由名称一致） -->
        <router-link v-if="route.name !== 'help'" class="help-link" :to="{ path: '/help', hash: `#${route.name}` }">帮助</router-link>
        <el-dropdown @command="onCommand">
          <span class="user">
            {{ auth.user?.username }}
            <el-tag size="small" :type="auth.isAdmin ? 'danger' : 'info'">{{ auth.isAdmin ? '管理员' : '只读' }}</el-tag>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">修改密码</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>

    <el-dialog v-model="pwDialog" title="修改密码" width="400px">
      <el-form :model="pwForm" label-width="80px">
        <el-form-item label="原密码"><el-input v-model="pwForm.old" type="password" show-password /></el-form-item>
        <el-form-item label="新密码"><el-input v-model="pwForm.new" type="password" show-password placeholder="至少 10 位" /></el-form-item>
        <el-form-item label="确认密码"><el-input v-model="pwForm.confirm" type="password" show-password /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwDialog = false">取消</el-button>
        <el-button type="primary" @click="changePassword">确定</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from './api'
import { auth, clearSession } from './auth'

const route = useRoute()
const router = useRouter()
const pwDialog = ref(false)
const pwForm = reactive({ old: '', new: '', confirm: '' })

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
    ElMessage.error('两次输入的新密码不一致')
    return
  }
  await api.changePassword(pwForm.old, pwForm.new)
  // 后端改密码后会让所有会话失效，需要重新登录。
  clearSession()
  pwDialog.value = false
  ElMessage.success('密码已修改，请重新登录')
  router.push({ name: 'login' })
}
</script>

<style scoped>
.help-link { margin-right: 16px; color: #409eff; font-size: 14px; text-decoration: none; }
.layout { height: 100%; }
.aside { background: #1f2d3d; }
.aside .el-menu { border-right: none; }
.logo { color: #fff; font-size: 16px; font-weight: 600; height: 60px; line-height: 60px; text-align: center; }
.header { background: #fff; display: flex; align-items: center; justify-content: flex-end; border-bottom: 1px solid #e4e7ed; }
.user { cursor: pointer; display: flex; align-items: center; gap: 8px; outline: none; }
</style>
