import { apiOrigin } from '../utils/csp'

/**
 * Optional relay of the API through the console's own origin (NUXT_API_PROXY_TARGET): the browser
 * then only talks to one origin (CSP `connect-src 'self'`, no CORS), as behind the Helm ingress.
 * Streams are passed through untouched (SSE of /logs/stream); headers are forwarded as received
 * (bearer, X-Afw-Session, X-Afw-Interface). Disabled when the variable is empty.
 */
export default defineEventHandler(async (event) => {
  const target = apiOrigin(String(useRuntimeConfig(event).apiProxyTarget ?? ''))
  if (!target) return
  const path = event.path
  if (!path.startsWith('/api/') && path !== '/healthz') return
  return proxyRequest(event, `${target}${path}`, { fetchOptions: { redirect: 'manual' } })
})
