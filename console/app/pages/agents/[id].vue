<script setup lang="ts">
import type { AgentOverview, FlowEvent, FlowStats } from '~/api/types'
import { flowRuleLabel } from '~/utils/format'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const problem = useProblem()
const route = useRoute()
const id = computed(() => String(route.params.id))

const ov = ref<AgentOverview | null>(null)
const volume = ref<FlowStats | null>(null)
const error = ref<string | null>(null)
const moveOpen = ref(false)

async function load(v: string) {
  error.value = null
  try {
    const since = new Date(Date.now() - 86_400_000).toISOString()
    const [o, st] = await Promise.all([api.agentOverview(v), api.flowStats({ agent: v, bucket: '1h', from: since })])
    ov.value = o
    volume.value = st
  }
  catch (e) {
    error.value = problem.text(e)
  }
}
watch(id, v => void load(v), { immediate: true })

useHead({ title: () => `${ov.value?.agent.name ?? t('nav.agents')} — agents-firewall` })

/** Flows per hour over 24 h, counted by the API (`GET /logs/flows/stats?agent=…&bucket=1h`). */
const points = computed(() => volume.value?.points ?? [])
const scaleTop = computed(() => {
  const max = Math.max(1, ...points.value.map(p => p.allow + p.deny + p.observed))
  const step = max <= 10 ? 10 : 10 ** Math.ceil(Math.log10(max)) / 2
  return Math.ceil(max / step) * step
})
const bars = computed(() => points.value.map(p => ({
  ok: Math.round(((p.allow + p.observed) / scaleTop.value) * 140),
  ko: Math.round((p.deny / scaleTop.value) * 140),
  tip: t('agent.barTip', { h: fmt.hm(p.at), ok: p.allow + p.observed, ko: p.deny }),
})))
const ticks = computed(() => {
  const v = points.value
  if (!v.length) return []
  return [0, 0.25, 0.5, 0.75].map(r => fmt.hm(v[Math.floor(r * v.length)]!.at)).concat(t('journal.now'))
})

const maxFlows = computed(() => Math.max(1, ...(ov.value?.top_destinations ?? []).map(d => d.flows)))
const destWidth = (n: number) => `${Math.max(2, Math.round(Math.sqrt(n / maxFlows.value) * 100))}%`
const deniedDestinations = computed(() => ov.value?.top_destinations.filter(d => d.denied > 0).length ?? 0)
const dest = (f: FlowEvent) => f.domain ?? f.dst

async function capture() {
  if (!ov.value) return
  try {
    await api.startCapture({ agent_id: ov.value.agent.id, duration_secs: 900 })
    toast.add({ title: t('flow.captureStarted', { agent: ov.value.agent.name }), icon: 'i-lucide-radio' })
  }
  catch (e) {
    problem.notify(e)
  }
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <header class="flex flex-wrap items-center gap-[10px] border-b border-line bg-panel px-4 py-[10px]">
      <AgentTabs :current="id" />
      <span class="flex-1" />
      <ShellPageHeaderTools />
    </header>

    <UAlert
      v-if="error"
      class="m-4"
      color="error"
      variant="subtle"
      :title="t('agent.notFound')"
      :description="error"
    />

    <div
      v-else-if="ov"
      class="flex flex-col gap-4 p-4"
    >
      <section
        :aria-label="t('agent.identity')"
        class="afw-card flex flex-wrap items-center gap-x-6 gap-y-[14px] px-4 py-[14px]"
      >
        <span class="flex size-11 items-center justify-center rounded-[10px] bg-sub text-text2">
          <UIcon
            name="i-lucide-bot"
            class="size-[22px]"
          />
        </span>
        <div class="flex flex-col gap-0.5">
          <div class="flex items-center gap-2">
            <h1 class="m-0 font-mono text-[19px] font-semibold">
              {{ ov.agent.name }}
            </h1>
            <span class="inline-flex items-center gap-[5px] rounded-full bg-ok-bg px-2 py-px text-[11.5px] font-[650] text-ok">
              <span class="size-1.5 rounded-full bg-ok" />{{ t('agent.active', { when: fmt.rel(ov.last_seen_at) }) }}
            </span>
          </div>
          <span class="font-mono text-[12px] text-text2">{{ ov.agent.addresses.join(', ') }}<template v-for="(v, k) in ov.agent.labels" :key="k"> · {{ k }}={{ v }}</template></span>
        </div>
        <dl class="m-0 flex flex-wrap gap-x-[22px] gap-y-1.5 text-xs">
          <div class="flex flex-col">
            <dt class="text-text3">
              {{ t('agent.zone') }}
            </dt><dd class="m-0 font-semibold">
              <NuxtLink :to="`/rules?zone=${ov.zone.id}`">
                {{ ov.zone.name }}
              </NuxtLink>
            </dd>
          </div>
          <div class="flex flex-col">
            <dt class="text-text3">
              {{ t('agent.gateway') }}
            </dt><dd class="m-0 font-mono">
              {{ ov.gateway?.name ?? '—' }}
            </dd>
          </div>
          <div class="flex flex-col">
            <dt class="text-text3">
              {{ t('agent.enrollment') }}
            </dt><dd class="m-0">
              {{ t(`kind.${ov.agent.kind}`) }}
            </dd>
          </div>
          <div class="flex flex-col">
            <dt class="text-text3">
              {{ t('agent.plugin') }}
            </dt><dd
              class="m-0 font-semibold"
              :class="ov.agent.hermes ? 'text-ok' : 'text-text3'"
            >
              {{ ov.agent.hermes ? t('agent.correlationOn') : t('agent.correlationOff') }}
            </dd>
          </div>
          <div
            v-if="ov.agent.mcp_admin"
            class="flex flex-col"
          >
            <dt class="text-text3">
              MCP
            </dt><dd class="m-0 font-semibold">
              {{ t('agents.mcpAgent') }}
            </dd>
          </div>
        </dl>
        <span class="flex-1" />
        <div class="flex flex-wrap gap-2">
          <UButton
            :to="{ path: '/', query: { q: `agent:${ov.agent.name}` } }"
            color="neutral"
            variant="outline"
          >
            {{ t('agent.seeJournal') }}
          </UButton>
          <UButton
            color="neutral"
            variant="outline"
            @click="capture"
          >
            {{ t('agent.pcap') }}
          </UButton>
          <UButton
            color="neutral"
            variant="outline"
            data-testid="agent-move"
            @click="moveOpen = true"
          >
            {{ t('agent.changeZone') }}
          </UButton>
        </div>
      </section>

      <section
        :aria-label="t('agent.kpis')"
        class="grid grid-cols-[repeat(auto-fit,minmax(min(200px,100%),1fr))] gap-[10px]"
      >
        <div class="afw-card flex flex-col gap-0.5 px-[14px] py-3">
          <span class="text-xs text-text3">{{ t('agent.kpi.flows') }}</span>
          <strong class="text-[22px] font-[650]">{{ fmt.num(ov.flows_24h) }}</strong>
          <span class="text-[11.5px] text-text3">{{ t('agent.kpi.flowsSub') }}</span>
        </div>
        <div class="afw-card flex flex-col gap-0.5 px-[14px] py-3">
          <span class="text-xs text-text3">{{ t('agent.kpi.sent') }}</span>
          <strong class="text-[22px] font-[650]">{{ fmt.bytes(ov.bytes_out_24h) }}</strong>
          <span class="text-[11.5px] text-text3">{{ t('agent.kpi.received', { v: fmt.bytes(ov.bytes_in_24h) }) }}</span>
        </div>
        <div class="afw-card flex flex-col gap-0.5 px-[14px] py-3">
          <span class="text-xs text-text3">{{ t('agent.kpi.denied') }}</span>
          <strong class="text-[22px] font-[650] text-ko">{{ ov.denied_24h }}</strong>
          <span class="text-[11.5px] text-text3">{{ t('agent.kpi.deniedDest', deniedDestinations) }}</span>
        </div>
        <div class="afw-card flex flex-col gap-0.5 px-[14px] py-3">
          <span class="text-xs text-text3">{{ t('agent.kpi.destinations') }}</span>
          <strong class="text-[22px] font-[650]">{{ ov.top_destinations.length }}</strong>
          <span
            class="text-[11.5px]"
            :class="ov.alerts.length ? 'font-semibold text-warn' : 'text-text3'"
          >{{ t('agent.kpi.alerts', ov.alerts.length) }}</span>
        </div>
      </section>

      <section
        aria-labelledby="vol-title"
        class="afw-card flex flex-col gap-[10px] px-4 py-[14px]"
      >
        <div class="flex flex-wrap items-baseline gap-3">
          <h2
            id="vol-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('agent.volume') }}
          </h2>
          <span class="text-xs text-text3">{{ t('agent.volumeSub') }}</span>
          <span class="flex-1" />
          <span class="flex items-center gap-3 text-[11.5px] text-text2">
            <span class="flex items-center gap-[5px]"><span class="size-[10px] rounded-[2px] bg-bar" />{{ t('verdict.allow') }}</span>
            <span class="flex items-center gap-[5px]"><span class="size-[10px] rounded-[2px] bg-ko" />{{ t('verdict.deny') }}</span>
          </span>
        </div>
        <div
          role="img"
          :aria-label="t('agent.volumeAria')"
          class="grid grid-cols-[40px_minmax(0,1fr)] gap-2"
        >
          <div class="flex h-[140px] flex-col justify-between text-right font-mono text-[10.5px] text-text3">
            <span>{{ fmt.num(scaleTop) }}</span><span>{{ fmt.num(scaleTop / 2) }}</span><span>0</span>
          </div>
          <div class="flex flex-col gap-1">
            <div
              class="flex h-[140px] items-end gap-1 border-b border-line2"
              style="background-image: linear-gradient(var(--line) 1px, transparent 1px); background-size: 100% 70px"
            >
              <div
                v-for="(b, i) in bars"
                :key="i"
                :title="b.tip"
                class="flex h-[140px] flex-1 flex-col justify-end"
              >
                <div
                  class="rounded-t-[2px] bg-ko"
                  :style="{ height: `${b.ko}px` }"
                />
                <div
                  class="bg-bar"
                  :class="b.ko ? '' : 'rounded-t-[2px]'"
                  :style="{ height: `${b.ok}px` }"
                />
              </div>
            </div>
            <div class="flex justify-between font-mono text-[10.5px] text-text3">
              <span
                v-for="(tk, i) in ticks"
                :key="i"
              >{{ tk }}</span>
            </div>
          </div>
        </div>
      </section>

      <div class="flex flex-wrap items-start gap-4">
        <section
          aria-labelledby="dest-title"
          class="afw-card min-w-0 flex-[999_1_560px] overflow-x-auto"
        >
          <div class="flex items-baseline gap-[10px] px-[14px] pt-3 pb-2">
            <h2
              id="dest-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('agent.destinations') }}
            </h2>
            <span class="text-xs text-text3">{{ t('agent.destinationsSub') }}</span>
          </div>
          <div class="min-w-[620px]">
            <div class="afw-th grid grid-cols-[minmax(200px,1.4fr)_60px_minmax(120px,1fr)_80px_96px] gap-[10px] border-y border-line px-[14px] py-1.5">
              <span>{{ t('agent.col.destination') }}</span><span>{{ t('agent.col.denied') }}</span><span>{{ t('agent.col.flows') }}</span><span>{{ t('agent.col.sent') }}</span><span>{{ t('agent.col.last') }}</span>
            </div>
            <div
              v-for="d in ov.top_destinations"
              :key="d.destination"
              class="grid grid-cols-[minmax(200px,1.4fr)_60px_minmax(120px,1fr)_80px_96px] items-center gap-[10px] border-b border-line px-[14px] py-[7px]"
            >
              <span class="flex min-w-0 items-center gap-1.5">
                <span class="truncate font-mono text-xs font-medium">{{ d.destination }}</span>
              </span>
              <span
                class="font-mono text-[11.5px]"
                :class="d.denied ? 'font-semibold text-ko' : 'text-text3'"
              >{{ d.denied || '—' }}</span>
              <span class="flex items-center gap-2">
                <span class="h-1.5 flex-1 overflow-hidden rounded-[3px] bg-sub"><span
                  class="block h-1.5"
                  :class="d.denied === d.flows ? 'bg-ko' : 'bg-bar'"
                  :style="{ width: destWidth(d.flows) }"
                /></span>
                <span class="w-12 text-right font-mono text-[11.5px]">{{ fmt.num(d.flows) }}</span>
              </span>
              <span class="font-mono text-[11.5px]">{{ fmt.bytes(d.bytes_out) }}</span>
              <span class="text-xs text-text3">{{ fmt.rel(d.last_seen_at) }}</span>
            </div>
          </div>
        </section>

        <div class="flex min-w-0 flex-[1_1_380px] flex-col gap-4">
          <section
            aria-labelledby="ko-title"
            class="afw-card flex flex-col gap-2 px-[14px] py-3"
          >
            <div class="flex items-baseline justify-between">
              <h2
                id="ko-title"
                class="m-0 text-sm font-[650]"
              >
                {{ t('agent.recentDenials') }}
              </h2>
              <NuxtLink
                :to="{ path: '/', query: { q: `agent:${ov.agent.name} verdict:deny` } }"
                class="text-xs"
              >{{ t('common.seeAll') }}</NuxtLink>
            </div>
            <ul class="m-0 flex list-none flex-col p-0">
              <li
                v-for="k in ov.recent_denied"
                :key="k.id"
                class="flex items-center gap-[10px] border-t border-line py-2"
              >
                <span class="flex min-w-0 flex-1 flex-col leading-[1.35]">
                  <span class="truncate font-mono text-xs font-semibold">{{ dest(k) }}</span>
                  <span class="text-[11.5px] text-text3">{{ fmt.rel(k.started_at) }} · {{ t('agent.ruleN', { n: flowRuleLabel(k) }) }} · {{ k.decision.reason }}</span>
                </span>
                <NuxtLink
                  v-if="k.decision.layer !== 'baseline'"
                  :to="`/flows/${k.id}`"
                  class="flex h-7 flex-none items-center rounded-md border border-line2 px-[10px] text-xs font-semibold no-underline"
                  style="color: var(--text)"
                >{{ t('agent.allowEllipsis') }}</NuxtLink>
                <span
                  v-else
                  class="flex-none text-[11px] text-text3"
                >{{ t('agent.baseline') }}</span>
              </li>
              <li
                v-if="!ov.recent_denied.length"
                class="border-t border-line py-2 text-text3"
              >
                {{ t('agent.noDenials') }}
              </li>
            </ul>
          </section>
          <section
            aria-labelledby="tools-title"
            class="afw-card flex flex-col gap-2 px-[14px] py-3"
          >
            <div class="flex items-baseline justify-between">
              <h2
                id="tools-title"
                class="m-0 text-sm font-[650]"
              >
                {{ t('agent.topTools') }}
              </h2>
              <span class="text-xs text-text3">{{ ov.agent.hermes ? 'Hermes' : '—' }}</span>
            </div>
            <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-xs">
              <li
                v-for="tool in ov.recent_tool_calls"
                :key="tool.id"
                class="flex justify-between gap-[10px]"
              >
                <span class="min-w-0 truncate font-mono">{{ tool.tool }}<span class="text-text3">({{ tool.args_summary }})</span></span>
                <span class="flex-none text-text2">{{ fmt.hm(tool.started_at) }}<template v-if="tool.status"> · {{ tool.status }}</template></span>
              </li>
              <li
                v-if="!ov.recent_tool_calls.length"
                class="text-text3"
              >
                {{ t('agent.noToolCalls') }}
              </li>
            </ul>
          </section>
          <section
            v-if="ov.alerts.length"
            aria-labelledby="alerts-title"
            class="afw-card flex flex-col gap-2 px-[14px] py-3"
          >
            <h2
              id="alerts-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('nav.alerts') }}
            </h2>
            <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-xs">
              <li
                v-for="a in ov.alerts"
                :key="a.id"
                class="flex flex-col"
              >
                <span class="font-semibold">{{ t(`alerts.kind.${a.kind}`) }} <span class="font-normal text-text3">· {{ fmt.rel(a.at) }}</span></span>
                <span class="text-text2">{{ a.summary }}</span>
              </li>
            </ul>
          </section>
        </div>
      </div>
    </div>
    <FormsAgentZoneForm
      v-model:open="moveOpen"
      :agent="ov?.agent ?? null"
      @saved="load(id)"
    />
  </div>
</template>
