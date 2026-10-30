import type { Session } from '~/api/types'

/** The caller's open policy session (Check Point–style: modify → publish → install). */
export function usePolicySession() {
  const session = useState<Session | null>('afw-session', () => null)
  const loaded = useState('afw-session-loaded', () => false)
  const api = useApi()

  async function refresh() {
    session.value = await api.currentSession()
    loaded.value = true
    return session.value
  }

  async function ensureOpen(name: string): Promise<Session> {
    if (session.value?.state === 'open') return session.value
    session.value = await api.openSession(name)
    return session.value
  }

  const changeCount = computed(() => session.value?.changes.length ?? 0)

  return { session, loaded, refresh, ensureOpen, changeCount }
}
