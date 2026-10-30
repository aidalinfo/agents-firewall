import type { AlertView, FlowStats, Gateway, PolicyStatus } from '~/api/types'

/** Data shared by the sidebar, the header and the status bar. Every figure comes from the API. */
export function useShell() {
  const api = useApi()
  const gateways = useAsyncData<Gateway[]>('shell-gateways', () => api.listGateways(), { default: () => [] })
  const alerts = useAsyncData<AlertView[]>('shell-alerts', () => api.listAlerts(), { default: () => [] })
  const stats = useAsyncData<FlowStats | null>('shell-stats', () => api.flowStats({}), { default: () => null })
  const policy = useAsyncData<PolicyStatus | null>('shell-policy', () => api.policyStatus(), { default: () => null })

  const openCritical = computed(() => alerts.data.value.filter(a => a.severity === 'critical' && !a.resolved).length)
  const openAlerts = computed(() => alerts.data.value.filter(a => !a.resolved).length)

  async function refreshShell() {
    await Promise.all([gateways.refresh(), alerts.refresh(), stats.refresh(), policy.refresh()])
  }

  return { gateways, alerts, stats, policy, openCritical, openAlerts, refreshShell }
}
