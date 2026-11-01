import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import enLocale from 'element-plus/es/locale/lang/en'
import 'element-plus/dist/index.css'
import App from './App.vue'
import router from './router'
import { lang, t } from './i18n'
import './style.css'

document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en'
document.title = t('内网防护系统')
const app = createApp(App)
app.config.globalProperties.t = t
app.use(router).use(ElementPlus, { locale: lang === 'zh' ? zhCn : enLocale }).mount('#app')
