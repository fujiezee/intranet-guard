<template>
  <div class="login">
    <el-card class="card">
      <h2>内网防护系统</h2>
      <el-form :model="form" @submit.prevent="submit">
        <el-form-item><el-input v-model="form.username" placeholder="用户名" autocomplete="username" /></el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码" autocomplete="current-password" show-password />
        </el-form-item>
        <el-button type="primary" native-type="submit" :loading="loading" style="width: 100%">登录</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import { setSession } from '../auth'

const route = useRoute()
const router = useRouter()
const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function submit() {
  loading.value = true
  try {
    const resp = await api.login(form.username, form.password)
    setSession(resp.token, resp.user)
    const redirect = route.query.redirect
    // 只允许站内跳转，防止开放重定向。
    router.push(typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/')
  } catch {
    // 错误提示已由 api 层弹出
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login { height: 100%; display: flex; align-items: center; justify-content: center; background: #1f2d3d; }
.card { width: 360px; }
h2 { text-align: center; margin: 0 0 24px; }
</style>
