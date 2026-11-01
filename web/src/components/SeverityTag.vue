<template>
  <el-tag :type="map[severity]?.type" size="small" effect="dark">{{ map[severity]?.label || severity }}</el-tag>
</template>

<script setup>
import { t } from '../i18n'
defineProps({ severity: String })
const map = {
  high: { type: 'danger', label: t('高') },
  medium: { type: 'warning', label: t('中') },
  low: { type: 'info', label: t('低') },
}
</script>
