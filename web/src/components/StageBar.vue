<template>
  <!-- 攻击链进度：按攻击推进顺序排列全部阶段，已出现的阶段高亮 -->
  <div class="bar">
    <el-tooltip v-for="s in all" :key="s.key" :content="s.name">
      <span class="step" :class="{ on: stages.includes(s.key) }">{{ s.short }}</span>
    </el-tooltip>
  </div>
</template>

<script setup>
import { t } from '../i18n'
defineProps({ stages: { type: Array, default: () => [] } })
const all = [
  { key: 'network', name: t('网络攻击'), short: t('网络') },
  { key: 'discovery', name: t('侦察探测'), short: t('侦察') },
  { key: 'credential', name: t('凭据获取'), short: t('凭据') },
  { key: 'initial', name: t('初始访问'), short: t('访问') },
  { key: 'execution', name: t('执行'), short: t('执行') },
  { key: 'persistence', name: t('持久化'), short: t('持久') },
  { key: 'evasion', name: t('防御规避'), short: t('规避') },
  { key: 'lateral', name: t('横向移动'), short: t('横向') },
  { key: 'c2', name: t('命令控制'), short: t('控制') },
  { key: 'exfil', name: t('数据外传'), short: t('外传') },
]
</script>

<style scoped>
.bar { display: flex; gap: 2px; }
.step { font-size: 11px; padding: 2px 6px; background: #f0f2f5; color: #c0c4cc; border-radius: 2px; }
.step.on { background: #f56c6c; color: #fff; }
</style>
