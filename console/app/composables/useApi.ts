import type { AfwApi } from '~/api/client'

export function useApi(): AfwApi {
  return useNuxtApp().$api as AfwApi
}
