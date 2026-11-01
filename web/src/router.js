import { createRouter, createWebHistory } from 'vue-router'
import { auth } from './auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
    { path: '/', name: 'dashboard', component: () => import('./views/Dashboard.vue') },
    { path: '/assets', name: 'assets', component: () => import('./views/Assets.vue') },
    { path: '/vulns', name: 'vulns', component: () => import('./views/Vulns.vue') },
    { path: '/ids', name: 'ids', component: () => import('./views/IDS.vue') },
    { path: '/hosts', name: 'hosts', component: () => import('./views/Hosts.vue') },
    { path: '/tasks', name: 'tasks', component: () => import('./views/Tasks.vue') },
    { path: '/alerts', name: 'alerts', component: () => import('./views/Alerts.vue') },
    { path: '/nodes', name: 'nodes', component: () => import('./views/Nodes.vue'), meta: { admin: true } },
    { path: '/settings', name: 'settings', component: () => import('./views/Settings.vue'), meta: { admin: true } },
    { path: '/users', name: 'users', component: () => import('./views/Users.vue'), meta: { admin: true } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (!to.meta.public && !auth.token) return { name: 'login', query: { redirect: to.fullPath } }
  if (to.meta.admin && !auth.isAdmin) return { name: 'dashboard' }
})

export default router
