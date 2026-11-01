<template>
  <el-tag :type="map[severity]?.type" size="small" effect="dark">{{ map[severity]?.label || severity }}</el-tag>
</template>

<script setup>
defineProps({ severity: String })
const map = {
  high: { type: 'danger', label: '高' },
  medium: { type: 'warning', label: '中' },
  low: { type: 'info', label: '低' },
}
</script>
