<script setup lang="ts">
import type { AgentListItem } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()

useHead({ title: () => `${t('nav.agents')} — agents-firewall` })

const { data: agents, status } = useAsyncData('agents', () => api.listAgents(), { default: () => [] as AgentListItem[] })

const columns = computed(() => [
  { accessorKey: 'name', header: t('agents.col.agent') },
  { accessorKey: 'zone', header: t('agents.col.zone') },
  { accessorKey: 'gateway', header: t('agents.col.gateway') },
  { accessorKey: 'kind', header: t('agents.col.enrollment') },
  { accessorKey: 'flows', header: t('agents.col.flows') },
  { accessorKey: 'denied', header: t('agents.col.denied') },
  { accessorKey: 'last', header: t('agents.col.last') },
])

const rows = computed(() => agents.value.map(a => ({
  id: a.agent.id,
  name: a.agent.name,
  description: a.description,
  zone: a.zone_name,
  gateway: a.gateway_name ?? '—',
  kind: t(`kind.${a.agent.kind}`),
  hermes: a.agent.hermes,
  mcp: a.agent.mcp_admin,
  flows: fmt.num(a.flows_24h),
  denied: a.denied_24h,
  last: fmt.rel(a.last_flow_at),
})))

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
            <span class="font-mono text-xs">@{{ row.original.zone }}</span>
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
  </div>
</template>
