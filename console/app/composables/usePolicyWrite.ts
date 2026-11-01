import type { Uuid } from '~/api/types'

/**
 * Runs a policy write in the caller's session (opened on demand), then reloads the session and
 * the directory. Errors are kept as text for the form: the API's own validation message is shown
 * as is (the console validates nothing itself).
 */
export function usePolicyWrite() {
  const { t } = useI18n()
  const { ensureOpen, refresh } = usePolicySession()
  const dir = useDirectory()
  const problem = useProblem()
  const busy = ref(false)
  const error = ref<string | null>(null)

  async function run<T>(fn: (sessionId: Uuid) => Promise<T>): Promise<T | null> {
    if (busy.value) return null
    busy.value = true
    error.value = null
    try {
      const s = await ensureOpen(t('rules.defaultSessionName'))
      const out = await fn(s.id)
      await refresh()
      await dir.refresh()
      return out
    }
    catch (e) {
      error.value = problem.text(e)
      return null
    }
    finally {
      busy.value = false
    }
  }

  /** Same, for writes outside policy sessions (alert channels, tokens). */
  async function plain<T>(fn: () => Promise<T>): Promise<T | null> {
    if (busy.value) return null
    busy.value = true
    error.value = null
    try {
      return await fn()
    }
    catch (e) {
      error.value = problem.text(e)
      return null
    }
    finally {
      busy.value = false
    }
  }

  return { busy, error, run, plain }
}
