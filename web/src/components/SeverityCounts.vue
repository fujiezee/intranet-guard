<template>
  <span class="counts">
    <el-tag type="danger" size="small">{{ t('高 {p0}', { p0: counts?.high || 0 }) }}</el-tag>
    <el-tag type="warning" size="small">{{ t('中 {p0}', { p0: counts?.medium || 0 }) }}</el-tag>
    <el-tag type="info" size="small">{{ t('低 {p0}', { p0: counts?.low || 0 }) }}</el-tag>
  </span>
</template>

<script setup>
import { t } from '../i18n'
defineProps({ counts: Object })
</script>

<style scoped>
.counts { display: inline-flex; gap: 4px; }
</style>
