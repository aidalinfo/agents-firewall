import type { Me } from '~/api/types'
import { readToken, writeToken } from '~/utils/token'

export function useAuth() {
  const me = useState<Me | null>('afw-me', () => null)
  const api = useApi()

  async function login(token: string): Promise<Me> {
    writeToken(token)
    try {
      me.value = await api.me()
      return me.value
    }
    catch (e) {
      writeToken(null)
      me.value = null
      throw e
    }
  }

  async function ensureMe(): Promise<Me | null> {
    if (me.value) return me.value
    if (!readToken()) return null
    try {
      me.value = await api.me()
    }
    catch {
      writeToken(null)
      me.value = null
    }
    return me.value
  }

  function logout() {
    writeToken(null)
    me.value = null
    return navigateTo('/login')
  }

  return { me, login, logout, ensureMe, hasToken: () => !!readToken() }
}
