import { describeProblem } from '~/utils/problem'

/** Toast (or text) for an API error, worded once for every form and action. */
export function useProblem() {
  const { t } = useI18n()
  const toast = useToast()

  function text(e: unknown): string {
    const p = describeProblem(e)
    const head = t(p.key, p.params)
    return p.detail ? `${head} — ${p.detail}` : head
  }

  function notify(e: unknown, title?: string) {
    toast.add({ title: title ?? text(e), description: title ? text(e) : undefined, color: 'error', icon: 'i-lucide-circle-alert' })
  }

  return { text, notify }
}
