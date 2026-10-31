import { ApiError } from '~/api/client'
import type { Approval, PublishOutcome, Session } from '~/api/types'

/**
 * The caller's policy session (Check Point–style: modify → publish → install). While a session is
 * open, policy reads carry it (`X-Afw-Session`) so that every page shows the draft.
 */
export function usePolicySession() {
  const session = useState<Session | null>('afw-session', () => null)
  const loaded = useState('afw-session-loaded', () => false)
  /** Approval requested by the last publish (202, EF-52), shown as a banner until decided. */
  const approval = useState<Approval | null>('afw-approval', () => null)
  const api = useApi()
  const directory = useDirectory()

  const isOpen = computed(() => session.value?.state === 'open')

  function apply(s: Session | null) {
    session.value = s
    api.setSession(s?.state === 'open' ? s.id : null)
  }

  async function refresh() {
    const before = session.value?.state === 'open' ? session.value.id : null
    apply(await api.currentSession())
    loaded.value = true
    if (approval.value && session.value?.approval_id !== approval.value.id) approval.value = null
    if ((session.value?.state === 'open' ? session.value.id : null) !== before) await directory.refresh()
    return session.value
  }

  async function ensureOpen(name: string): Promise<Session> {
    if (session.value?.state === 'open') return session.value
    try {
      apply(await api.openSession(name))
    }
    catch (e) {
      // 409: a session is already open for this caller (opened elsewhere): resume it.
      if (!(e instanceof ApiError && e.status === 409)) throw e
      await refresh()
      if ((session.value as Session | null)?.state !== 'open') throw e
    }
    return session.value!
  }

  async function publish(comment: string): Promise<PublishOutcome> {
    const s = session.value
    if (!s) throw new Error('no session')
    const out = await api.publishSession(s.id, comment)
    if (out.status === 'approval') approval.value = out.approval
    await refresh()
    return out
  }

  async function discard() {
    const s = session.value
    if (!s) return
    await api.discardSession(s.id)
    await refresh()
  }

  const changeCount = computed(() => (session.value?.state === 'open' ? session.value.changes : 0))

  return { session, loaded, approval, isOpen, refresh, ensureOpen, publish, discard, changeCount }
}
