import { contentSecurityPolicy, inlineScriptHashes, STATIC_SECURITY_HEADERS } from '../utils/csp'

/**
 * Security headers on every response served by Nitro (HTML shell and static assets).
 * The CSP is computed at runtime because the API origin (NUXT_PUBLIC_API_BASE) is a runtime setting
 * and the inline scripts Nuxt emits (runtime config, color mode) are allowed by hash only.
 */
export default defineNitroPlugin((nitroApp) => {
  if (import.meta.dev) return

  nitroApp.hooks.hook('request', (event) => {
    const apiBase = String(useRuntimeConfig(event).public.apiBase ?? '')
    for (const [k, v] of Object.entries(STATIC_SECURITY_HEADERS)) setResponseHeader(event, k, v)
    setResponseHeader(event, 'content-security-policy', contentSecurityPolicy({ apiBase }))
  })

  nitroApp.hooks.hook('render:response', (response, { event }) => {
    const apiBase = String(useRuntimeConfig(event).public.apiBase ?? '')
    const html = typeof response.body === 'string' ? response.body : ''
    const csp = contentSecurityPolicy({ apiBase, scriptHashes: inlineScriptHashes(html) })
    response.headers = { ...response.headers, ...STATIC_SECURITY_HEADERS, 'content-security-policy': csp }
    setResponseHeader(event, 'content-security-policy', csp)
  })
})
