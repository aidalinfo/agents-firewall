<script setup lang="ts">
import type { Agent, AgentOverview } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const dir = useDirectory()

useHead({ title: () => `${t('nav.agents')} — agents-firewall` })

/** Agents and their 24 h counters, both from the API (one overview per agent, EF-43). */
const { data: agents, status } = useAsyncData('agents', async () => {
  await dir.refresh()
  const overviews = await Promise.all(dir.data.value.agents.map(a => api.agentOverview(a.id).catch(() => null)))
  return dir.data.value.agents.map((agent, i) => ({ agent, overview: overviews[i] }))
}, { default: () => [] as { agent: Agent, overview: AgentOverview | null }[] })
const moveOpen = ref(false)
const moving = ref<Agent | null>(null)

const columns = computed(() => [
  { accessorKey: 'name', header: t('agents.col.agent') },
  { accessorKey: 'zone', header: t('agents.col.zone') },
  { accessorKey: 'gateway', header: t('agents.col.gateway') },
  { accessorKey: 'kind', header: t('agents.col.enrollment') },
  { accessorKey: 'flows', header: t('agents.col.flows') },
  { accessorKey: 'denied', header: t('agents.col.denied') },
  { accessorKey: 'last', header: t('agents.col.last') },
])

const rows = computed(() => agents.value.map(({ agent, overview }) => ({
  id: agent.id,
  agent,
  name: agent.name,
  description: agent.addresses.join(', '),
  zone: dir.zoneName(agent.zone_id) ?? '—',
  gateway: dir.gatewayName(agent.gateway_id) ?? '—',
  kind: t(`kind.${agent.kind}`),
  hermes: agent.hermes,
  mcp: agent.mcp_admin,
  flows: overview ? fmt.num(overview.flows_24h) : '—',
  denied: overview?.denied_24h ?? 0,
  last: fmt.rel(overview?.last_seen_at),
})))

function move(a: Agent) {
  moving.value = a
  moveOpen.value = true
}

function open(_e: Event, row: { original: { id: string } }) {
  void navigateTo(`/agents/${row.original.id}`)
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.agents')"
      :subtitle="t('agents.subtitle')"
    />
    <div class="p-4">
      <div class="afw-card overflow-hidden">
        <UTable
          :data="rows"
          :columns="columns"
          :loading="status === 'pending'"
          :ui="{ th: 'afw-th py-2', td: 'py-2 text-[12.5px]', tr: 'cursor-pointer hover:bg-sub' }"
          @select="open"
        >
          <template #name-cell="{ row }">
            <div class="flex flex-col leading-[1.3]">
              <span class="flex items-center gap-1.5">
                <NuxtLink
                  :to="`/agents/${row.original.id}`"
                  class="font-mono text-xs font-semibold no-underline"
                  style="color: var(--text)"
                >{{ row.original.name }}</NuxtLink>
                <UBadge
                  v-if="row.original.hermes"
                  size="sm"
                  variant="subtle"
                  color="success"
                >Hermes</UBadge>
                <UBadge
                  v-if="row.original.mcp"
                  size="sm"
                  variant="subtle"
                  color="info"
                >{{ t('agents.mcpAgent') }}</UBadge>
              </span>
              <span class="text-[11.5px] text-text3">{{ row.original.description }}</span>
            </div>
          </template>
          <template #zone-cell="{ row }">
            <span class="flex items-center gap-1.5">
              <span class="font-mono text-xs">@{{ row.original.zone }}</span>
              <button
                type="button"
                class="afw-ghost flex size-5 items-center justify-center rounded"
                :aria-label="t('agents.move.button')"
                :data-testid="`agent-move-${row.original.name}`"
                @click.stop="move(row.original.agent)"
              >
                <UIcon
                  name="i-lucide-move"
                  class="size-3"
                />
              </button>
            </span>
          </template>
          <template #gateway-cell="{ row }">
            <span class="font-mono text-xs">{{ row.original.gateway }}</span>
          </template>
          <template #denied-cell="{ row }">
            <span
              class="font-mono text-xs font-semibold"
              :class="row.original.denied ? 'text-ko' : 'text-text3'"
            >{{ row.original.denied }}</span>
          </template>
        </UTable>
      </div>
    </div>
    <FormsAgentZoneForm
      v-model:open="moveOpen"
      :agent="moving"
      @saved="refreshNuxtData('agents')"
    />
  </div>
</template>
