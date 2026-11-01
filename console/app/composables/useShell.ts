import type { Alert, FlowStats, Gateway, PolicyStatus } from '~/api/types'

/** Data shared by the sidebar, the header and the status bar. Every figure comes from the API. */
export function useShell() {
  const api = useApi()
  const gateways = useAsyncData<Gateway[]>('shell-gateways', () => api.listGateways(), { default: () => [] })
  const alerts = useAsyncData<Alert[]>('shell-alerts', async () => (await api.listAlerts({ acknowledged: false })).items, { default: () => [] })
  const stats = useAsyncData<FlowStats | null>('shell-stats', () => api.flowStats({ bucket: '1m' }), { default: () => null })
  const policy = useAsyncData<PolicyStatus | null>('shell-policy', () => api.policyStatus(), { default: () => null })

  const openCritical = computed(() => alerts.data.value.filter(a => a.event.severity === 'critical').length)
  const openAlerts = computed(() => alerts.data.value.length)
  /** Flows of the last complete minute (bucket 1m). */
  const perMinute = computed(() => {
    const p = stats.data.value?.points.at(-2)
    return p ? p.allow + p.deny + p.observed : 0
  })

  async function refreshShell() {
    await Promise.all([gateways.refresh(), alerts.refresh(), stats.refresh(), policy.refresh()])
  }

  return { gateways, alerts, stats, policy, openCritical, openAlerts, perMinute, refreshShell }
}
