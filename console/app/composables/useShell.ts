import type { AlertView, FlowStats, Gateway } from '~/api/types'

/** Data shared by the sidebar, the header and the status bar. */
export function useShell() {
  const api = useApi()
  const gateways = useAsyncData<Gateway[]>('shell-gateways', () => api.listGateways(), { default: () => [] })
  const alerts = useAsyncData<AlertView[]>('shell-alerts', () => api.listAlerts(), { default: () => [] })
  const stats = useAsyncData<FlowStats | null>('shell-stats', () => api.flowStats({}), { default: () => null })

  const openCritical = computed(() => alerts.data.value.filter(a => a.severity === 'critical' && !a.resolved).length)
  const openAlerts = computed(() => alerts.data.value.filter(a => !a.resolved).length)
  const installedRevision = computed(() => {
    const revs = gateways.data.value.map(g => g.revision ?? 0)
    return revs.length ? Math.max(...revs) : null
  })
  const p95 = computed(() => {
    const online = gateways.data.value.filter(g => g.status === 'online')
    return online.length ? Math.min(...online.map(g => g.stats.latency_p95_ms)) : null
  })

  async function refreshShell() {
    await Promise.all([gateways.refresh(), alerts.refresh(), stats.refresh()])
  }

  return { gateways, alerts, stats, openCritical, openAlerts, installedRevision, p95, refreshShell }
}
