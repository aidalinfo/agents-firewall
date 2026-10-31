import type { Agent, DataClass, Gateway, NetObject, Service, Uuid, Zone } from '~/api/types'

/**
 * Policy resources and gateways as listed by the API (draft of the open session when there is
 * one), to show names where the contract gives ids. Presentation only: no policy decision is
 * derived from it.
 */
export function useDirectory() {
  const api = useApi()
  const data = useState('afw-directory', () => ({
    zones: [] as Zone[],
    agents: [] as Agent[],
    objects: [] as NetObject[],
    services: [] as Service[],
    dataClasses: [] as DataClass[],
    gateways: [] as Gateway[],
    loaded: false,
  }))
  const pending = useState<Promise<void> | null>('afw-directory-pending', () => null)

  async function refresh(): Promise<void> {
    const p = (async () => {
      const [zones, agents, objects, services, dataClasses, gateways] = await Promise.all([
        api.zones.list(), api.agents.list(), api.objects.list(), api.services.list(), api.dataClasses.list(), api.listGateways(),
      ])
      data.value = { zones, agents, objects, services, dataClasses, gateways, loaded: true }
    })()
    pending.value = p
    try {
      await p
    }
    finally {
      if (pending.value === p) pending.value = null
    }
  }

  async function ensure(): Promise<void> {
    if (data.value.loaded) return
    await (pending.value ?? refresh())
  }

  const byId = <T extends { id: Uuid, name: string }>(list: T[], id: Uuid | null | undefined) => (id ? list.find(x => x.id === id) : undefined)
  const name = <T extends { id: Uuid, name: string }>(list: T[], id: Uuid | null | undefined) => byId(list, id)?.name ?? null

  return {
    data,
    refresh,
    ensure,
    zone: (id: Uuid | null | undefined) => byId(data.value.zones, id),
    agent: (id: Uuid | null | undefined) => byId(data.value.agents, id),
    zoneName: (id: Uuid | null | undefined) => name(data.value.zones, id),
    agentName: (id: Uuid | null | undefined) => name(data.value.agents, id),
    gatewayName: (id: Uuid | null | undefined) => name(data.value.gateways, id),
    objectName: (id: Uuid | null | undefined) => name(data.value.objects, id),
    serviceName: (id: Uuid | null | undefined) => name(data.value.services, id),
    dataClassName: (id: Uuid | null | undefined) => name(data.value.dataClasses, id),
    zoneAgents: (id: Uuid | null | undefined) => data.value.agents.filter(a => a.zone_id === id),
  }
}
