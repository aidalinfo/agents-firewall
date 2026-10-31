<script setup lang="ts">
import type { AlertChannel, InternalMap, MapEdge, MapNode, MapPeriod } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const problem = useProblem()
const dir = useDirectory()
const { alerts, refreshShell } = useShell()

useHead({ title: () => `${t('nav.internal')} — agents-firewall` })

const period = ref<MapPeriod>('24h')
const map = ref<InternalMap | null>(null)
const channels = ref<AlertChannel[]>([])

watch(period, async (p) => {
  try {
    map.value = await api.internalMap(p)
  }
  catch (e) {
    problem.notify(e)
  }
}, { immediate: true })
onMounted(async () => {
  void dir.ensure()
  channels.value = await api.alertChannels.list().catch(() => [])
})

const W = 820
const NODE_H = 44
const H = computed(() => Math.max(260, 60 + Math.max(agentsN.value, systemsN.value) * 58))
const agentsN = computed(() => map.value?.nodes.filter(n => n.kind === 'agent').length ?? 0)
const systemsN = computed(() => map.value?.nodes.filter(n => n.kind !== 'agent').length ?? 0)

/** Edge state shown on the map: an alert raised on it, or first seen in the period (lateral movement hint). */
const edgeState = (e: MapEdge) => (e.alerts > 0 ? 'alert' : e.new ? 'new' : 'usual')

const layout = computed(() => {
  const nodes = map.value?.nodes ?? []
  const agents = nodes.filter(n => n.kind === 'agent')
  const systems = nodes.filter(n => n.kind !== 'agent')
  const edges = map.value?.edges ?? []
  const place = (list: MapNode[], x: number, w: number, top: number, bottom: number) =>
    list.map((n, i) => {
      const touching = edges.filter(e => e.source === n.id || e.target === n.id)
      const state = touching.some(e => e.alerts > 0) ? 'alert' : touching.length && touching.every(e => e.new) ? 'new' : 'normal'
      const sub = n.kind === 'agent' ? `@${dir.zoneName(n.zone_id) ?? ''}` : (n.address && n.address !== n.label ? n.address : t('internal.internalHost'))
      return { ...n, state, sub, href: n.kind === 'agent' && n.agent_id ? `/agents/${n.agent_id}` : null, x, w, y: list.length === 1 ? top : Math.round(top + (i * (bottom - top)) / (list.length - 1)) }
    })
  return [...place(agents, 40, 170, 40, H.value - 90), ...place(systems, 600, 210, 20, H.value - 60)]
})

const maxFlows = computed(() => Math.max(1, ...(map.value?.edges ?? []).map(e => e.flows)))
const edges = computed(() => {
  const pos = new Map(layout.value.map(n => [n.id, n]))
  return (map.value?.edges ?? []).flatMap((e) => {
    const a = pos.get(e.source)
    const b = pos.get(e.target)
    if (!a || !b) return []
    const y1 = a.y + NODE_H / 2
    const y2 = b.y + NODE_H / 2
    const d = b.kind === 'agent'
      ? `M40 ${y1} C-2 ${y1} -2 ${y2} 40 ${y2}`
      : `M210 ${y1} C400 ${y1} 410 ${y2} 600 ${y2}`
    const state = edgeState(e)
    const stroke = state === 'alert' ? 'var(--ko)' : state === 'new' ? 'var(--warn)' : 'var(--edge)'
    const dash = state === 'alert' ? '6 4' : state === 'new' ? '5 4' : undefined
    const weight = 1 + Math.round(Math.log2(1 + (e.flows / maxFlows.value) * 31))
    return [{ d, stroke, width: state === 'usual' ? weight : Math.min(weight, 2.5), dash, key: `${e.source}-${e.target}-${e.port}`, agentToAgent: b.kind === 'agent', labelY: Math.round((y1 + y2) / 2) - 8 }]
  })
})

const nodeLabel = (id: string) => map.value?.nodes.find(n => n.id === id)?.label ?? id
const connections = computed(() => [...(map.value?.edges ?? [])].sort((a, b) => b.last_seen_at.localeCompare(a.last_seen_at)))
const highCount = computed(() => alerts.data.value.filter(a => a.event.severity === 'critical').length)
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.internal')"
      :subtitle="t('internal.subtitle')"
    >
      <template #actions>
        <div
          role="group"
          :aria-label="t('internal.period')"
          class="flex h-8 overflow-hidden rounded-[7px] border border-line2"
        >
          <button
            v-for="p in (['1h', '24h', '7d'] as const)"
            :key="p"
            type="button"
            class="border-0 px-3 text-[12.5px] font-semibold"
            :class="period === p ? 'bg-text text-bg' : 'bg-transparent text-text2'"
            :aria-pressed="period === p"
            @click="period = p"
          >
            {{ t(`internal.p.${p}`) }}
          </button>
        </div>
      </template>
    </ShellPageHeader>

    <div class="flex flex-wrap items-start gap-4 p-4">
      <div class="flex min-w-0 flex-[999_1_640px] flex-col gap-4">
        <section
          aria-labelledby="map-title"
          class="afw-card flex flex-col gap-[10px] px-4 py-[14px]"
        >
          <div class="flex flex-wrap items-baseline gap-3">
            <h2
              id="map-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('internal.map') }}
            </h2>
            <span class="text-xs text-text3">{{ t('internal.mapSub') }}</span>
            <span class="flex-1" />
            <span class="flex items-center gap-[14px] text-[11.5px] text-text2">
              <span class="flex items-center gap-1.5"><span class="h-[3px] w-[18px] rounded-sm bg-edge" />{{ t('internal.usual') }}</span>
              <span class="flex items-center gap-1.5"><span class="h-0 w-[18px] border-t-2 border-dashed border-warn" />{{ t('internal.new') }}</span>
              <span class="flex items-center gap-1.5"><span class="h-0 w-[18px] border-t-2 border-dashed border-ko" />{{ t('internal.alert') }}</span>
            </span>
          </div>
          <div class="overflow-x-auto">
            <div
              class="relative mx-auto"
              :style="{ width: `${W}px`, height: `${H}px` }"
              data-testid="internal-map"
            >
              <svg
                aria-hidden="true"
                :width="W"
                :height="H"
                :viewBox="`0 0 ${W} ${H}`"
                fill="none"
                class="absolute inset-0 overflow-visible"
              >
                <path
                  v-for="e in edges"
                  :key="e.key"
                  :d="e.d"
                  :style="{ stroke: e.stroke, strokeWidth: e.width, strokeDasharray: e.dash }"
                />
              </svg>
              <span class="absolute top-0 left-10 text-[10.5px] font-semibold tracking-[.05em] text-text3 uppercase">{{ t('internal.agents') }}</span>
              <span class="absolute top-0 left-[600px] text-[10.5px] font-semibold tracking-[.05em] text-text3 uppercase">{{ t('internal.systems') }}</span>
              <template
                v-for="e in edges"
                :key="`l-${e.key}`"
              >
                <span
                  v-if="e.agentToAgent"
                  class="absolute left-0 rounded bg-panel px-1 py-px text-[10.5px] font-semibold whitespace-nowrap text-ko"
                  :style="{ top: `${e.labelY}px` }"
                >{{ t('internal.agentToAgent') }}</span>
              </template>
              <component
                :is="n.href ? 'a' : 'div'"
                v-for="n in layout"
                :key="n.id"
                :href="n.href ?? undefined"
                class="absolute flex flex-col justify-center rounded-lg px-[10px] py-1 leading-[1.2] no-underline"
                :class="[
                  n.kind === 'agent' ? 'border border-line2 bg-panel' : n.state === 'alert' ? 'border border-ko bg-ko-bg' : n.state === 'new' ? 'border-[1.5px] border-dashed border-warn bg-warn-bg' : 'border border-line2 bg-sub',
                ]"
                :style="{ left: `${n.x}px`, top: `${n.y}px`, width: `${n.w}px`, height: `${NODE_H}px`, color: 'var(--text)' }"
                @click.prevent="n.href && navigateTo(n.href)"
              >
                <strong
                  class="text-xs"
                  :class="n.kind === 'agent' || n.state === 'new' ? 'font-mono' : ''"
                >{{ n.label }}</strong>
                <span
                  class="text-[10.5px]"
                  :class="n.state === 'alert' ? 'font-semibold text-ko' : n.state === 'new' ? 'font-semibold text-warn' : dir.zone(n.zone_id)?.mode === 'observe' ? 'text-obs' : 'text-text3'"
                >{{ n.sub }}<template v-if="dir.zone(n.zone_id)?.mode === 'observe'"> · {{ t('zone.observation') }}</template></span>
              </component>
            </div>
          </div>
        </section>

        <section
          aria-labelledby="conn-title"
          class="afw-card overflow-x-auto"
        >
          <div class="flex items-baseline gap-[10px] px-[14px] pt-3 pb-2">
            <h2
              id="conn-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('internal.connections') }}
            </h2>
            <span class="text-xs text-text3">{{ t('internal.connectionsSub') }}</span>
          </div>
          <div class="min-w-[640px]">
            <div class="afw-th grid grid-cols-[120px_minmax(140px,1fr)_96px_70px_80px_86px_80px] gap-[10px] border-y border-line px-[14px] py-1.5">
              <span>{{ t('internal.col.agent') }}</span><span>{{ t('internal.col.target') }}</span><span>{{ t('internal.col.port') }}</span><span>{{ t('internal.col.flows') }}</span><span>{{ t('internal.col.volume') }}</span><span>{{ t('internal.col.last') }}</span><span>{{ t('internal.col.signal') }}</span>
            </div>
            <div
              v-for="e in connections"
              :key="`${e.source}-${e.target}-${e.port}`"
              class="grid grid-cols-[120px_minmax(140px,1fr)_96px_70px_80px_86px_80px] items-center gap-[10px] border-b border-line px-[14px] py-[7px] text-xs"
            >
              <span class="truncate font-mono text-[11.5px]">{{ nodeLabel(e.source) }}</span>
              <span class="truncate font-mono text-[11.5px]">{{ nodeLabel(e.target) }}</span>
              <span class="font-mono text-[11.5px] text-text2">{{ e.protocol }}/{{ e.port }}<template v-if="e.app"> · {{ e.app }}</template></span>
              <span class="font-mono text-[11.5px]">{{ fmt.num(e.flows) }}</span>
              <span class="font-mono text-[11.5px] text-text2">{{ fmt.bytes(e.bytes) }}</span>
              <span class="text-text3">{{ fmt.rel(e.last_seen_at) }}</span>
              <span><span
                v-if="edgeState(e) !== 'usual'"
                class="rounded px-1.5 py-px text-[11px] font-bold"
                :class="edgeState(e) === 'alert' ? 'bg-ko-bg text-ko' : 'bg-warn-bg text-warn'"
              >{{ t(`internal.${edgeState(e)}`) }}</span></span>
            </div>
            <div
              v-if="!connections.length"
              class="px-[14px] py-4 text-center text-text3"
            >
              {{ t('internal.none') }}
            </div>
          </div>
        </section>
      </div>

      <section
        aria-labelledby="alerts-title"
        class="afw-card flex min-w-0 flex-[1_1_380px] flex-col"
      >
        <div class="flex items-center gap-[10px] border-b border-line px-[14px] py-3">
          <h2
            id="alerts-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('nav.alerts') }}
          </h2>
          <span
            v-if="highCount"
            class="rounded-full bg-ko-bg px-2 text-[11.5px] font-bold text-ko"
          >{{ t('alerts.high', highCount) }}</span>
          <span class="flex-1" />
          <NuxtLink
            to="/alerts"
            class="flex h-7 items-center rounded-md border border-line2 px-[10px] text-xs font-medium no-underline"
            style="color: var(--text)"
          >{{ t('alerts.channels', { list: channels.map(c => c.name).join(', ') }) }}</NuxtLink>
        </div>
        <AlertsAlertList
          :alerts="alerts.data.value"
          @changed="refreshShell"
        />
      </section>
    </div>
  </div>
</template>
