/** Every page but /login requires a token (OIDC access token or API token). */
export default defineNuxtRouteMiddleware(async (to) => {
  if (to.path === '/login') return
  const { ensureMe } = useAuth()
  const me = await ensureMe()
  if (!me) return navigateTo({ path: '/login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : {} })
})
