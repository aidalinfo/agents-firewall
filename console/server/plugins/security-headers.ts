import { contentSecurityPolicy, inlineScriptHashes, STATIC_SECURITY_HEADERS } from '../utils/csp'

/**
 * Security headers on every response served by Nitro (HTML shell and static assets).
 * The CSP is computed at runtime because the API origin (NUXT_PUBLIC_API_BASE) is a runtime setting
 * and the inline scripts Nuxt emits (runtime config, color mode) are allowed by hash only.
 */
export default defineNitroPlugin((nitroApp) => {
  if (import.meta.dev) return

  const origins = (event: Parameters<typeof useRuntimeConfig>[0]) => {
    const config = useRuntimeConfig(event)
    return { apiBase: String(config.public.apiBase ?? ''), oidcOrigin: String(config.oidcConnectSrc ?? '') }
  }

  nitroApp.hooks.hook('request', (event) => {
    for (const [k, v] of Object.entries(STATIC_SECURITY_HEADERS)) setResponseHeader(event, k, v)
    setResponseHeader(event, 'content-security-policy', contentSecurityPolicy(origins(event)))
  })

  nitroApp.hooks.hook('render:response', (response, { event }) => {
    const html = typeof response.body === 'string' ? response.body : ''
    const csp = contentSecurityPolicy({ ...origins(event), scriptHashes: inlineScriptHashes(html) })
    response.headers = { ...response.headers, ...STATIC_SECURITY_HEADERS, 'content-security-policy': csp }
    setResponseHeader(event, 'content-security-policy', csp)
  })
})
