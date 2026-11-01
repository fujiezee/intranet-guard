<template>
  <div>
    <div class="page-header">
      <h2>用户管理</h2>
      <el-button type="primary" @click="openDialog">新建用户</el-button>
    </div>
    <el-table :data="users" v-loading="loading" stripe>
      <el-table-column prop="id" label="ID" width="70" />
      <el-table-column prop="username" label="用户名" />
      <el-table-column label="角色" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="row.role === 'admin' ? 'danger' : 'info'">{{ row.role === 'admin' ? '管理员' : '只读' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="创建时间" width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
      <el-table-column label="操作" width="100">
        <template #default="{ row }">
          <el-button v-if="row.id !== auth.user?.id" size="small" type="danger" link @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="dialog" title="新建用户" width="420px">
      <el-form :model="form" label-width="70px">
        <el-form-item label="用户名"><el-input v-model="form.username" /></el-form-item>
        <el-form-item label="密码"><el-input v-model="form.password" type="password" show-password placeholder="至少 10 位" /></el-form-item>
        <el-form-item label="角色">
          <el-radio-group v-model="form.role">
            <el-radio value="viewer">只读</el-radio>
            <el-radio value="admin">管理员</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" @click="submit">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const users = ref([])
const loading = ref(false)
const dialog = ref(false)
const form = reactive({ username: '', password: '', role: 'viewer' })

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
  ElMessage.success('用户已创建')
  dialog.value = false
  load()
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确定删除用户 ${row.username}？`, '删除用户', { type: 'warning' })
  } catch {
    return // 用户取消
  }
  await api.deleteUser(row.id)
  ElMessage.success('已删除')
  load()
}

onMounted(load)
</script>
