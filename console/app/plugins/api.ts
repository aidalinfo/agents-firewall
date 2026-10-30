import type { AfwApi, ApiMode } from '~/api/client'
import { createHttpApi } from '~/api/http'
import { createMockApi } from '~/api/mock'
import { TOKEN_KEY, readToken } from '~/utils/token'

/** Provides `$api`: the mock or the HTTP implementation, chosen by NUXT_PUBLIC_API_MODE. */
export default defineNuxtPlugin(() => {
  const config = useRuntimeConfig().public
  const mode = (config.apiMode === 'http' ? 'http' : 'mock') as ApiMode
  const api: AfwApi = mode === 'http'
    ? createHttpApi({
        baseUrl: String(config.apiBase ?? ''),
        getToken: readToken,
        onUnauthorized: () => {
          try {
            sessionStorage.removeItem(TOKEN_KEY)
          }
          catch {
            // storage unavailable
          }
          const route = useRouter().currentRoute.value
          if (route.path !== '/login') void navigateTo({ path: '/login', query: { redirect: route.fullPath } })
        },
      })
    : createMockApi({ latencyMs: Number(config.mockLatencyMs ?? 120) })
  return { provide: { api, apiMode: mode } }
})
