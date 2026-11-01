<template>
  <!-- 攻击链进度：按攻击推进顺序排列全部阶段，已出现的阶段高亮 -->
  <div class="bar">
    <el-tooltip v-for="s in all" :key="s.key" :content="s.name">
      <span class="step" :class="{ on: stages.includes(s.key) }">{{ s.short }}</span>
    </el-tooltip>
  </div>
</template>

<script setup>
defineProps({ stages: { type: Array, default: () => [] } })
const all = [
  { key: 'network', name: '网络攻击', short: '网络' },
  { key: 'discovery', name: '侦察探测', short: '侦察' },
  { key: 'credential', name: '凭据获取', short: '凭据' },
  { key: 'initial', name: '初始访问', short: '访问' },
  { key: 'execution', name: '执行', short: '执行' },
  { key: 'persistence', name: '持久化', short: '持久' },
  { key: 'evasion', name: '防御规避', short: '规避' },
  { key: 'lateral', name: '横向移动', short: '横向' },
  { key: 'c2', name: '命令控制', short: '控制' },
  { key: 'exfil', name: '数据外传', short: '外传' },
]
</script>

<style scoped>
.bar { display: flex; gap: 2px; }
.step { font-size: 11px; padding: 2px 6px; background: #f0f2f5; color: #c0c4cc; border-radius: 2px; }
.step.on { background: #f56c6c; color: #fff; }
</style>
