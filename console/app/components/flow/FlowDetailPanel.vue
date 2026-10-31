<script setup lang="ts">
import type { AllowDestination, FlowDetail, FlowListItem, RuleView, Track } from '~/api/types'
import { allowRuleCli, curlFor, httpReason } from '~/utils/cli'
import { flowRuleLabel, shortFlowId, splitSocket, verdictTone } from '~/utils/format'
import { bodyView } from '~/utils/security'

const props = defineProps<{
  detail: FlowDetail | null
  /** Row of the journal when known (names and labels computed by the API). */
  item?: FlowListItem | null
  loading?: boolean
  /** Full-page variant (/flows/[id]). */
  standalone?: boolean
}>()
const emit = defineEmits<{ added: [RuleView] }>()

const { t } = useI18n()
const fmt = useFmt()
const api = useApi()
const copy = useCopy()
const toast = useToast()
const problem = useProblem()
const dir = useDirectory()
const { session, ensureOpen, refresh: refreshSession } = usePolicySession()

onMounted(() => void dir.ensure())

type Mode = 'tabs' | 'allow' | 'added'
const mode = ref<Mode>('tabs')
const tab = ref<'http' | 'agent' | 'meta'>('http')
const destKey = ref<AllowDestination>('exact')
const expiry = ref<number | null>(30)
const track = ref<Track>('detailed')
const busy = ref(false)
const added = ref<RuleView | null>(null)
const nextRevision = computed(() => session.value?.next_revision ?? null)

watch(() => props.detail?.flow.id, () => {
  mode.value = 'tabs'
  destKey.value = 'exact'
  expiry.value = 30
  track.value = 'detailed'
  added.value = null
})

const flow = computed(() => props.detail?.flow ?? null)
const item = computed(() => (props.item && props.item.id === flow.value?.id ? props.item : null))
const agentName = computed(() => item.value?.agent_name ?? dir.agentName(flow.value?.agent_id) ?? flow.value?.src ?? '')
const zoneName = computed(() => item.value?.zone_name ?? dir.zoneName(flow.value?.zone_id) ?? '—')
const gatewayName = computed(() => dir.gatewayName(flow.value?.gateway_id) ?? flow.value?.gateway_id ?? '')
const ruleLabel = computed(() => item.value?.rule_label ?? (flow.value ? flowRuleLabel(flow.value) : ''))
const fid = computed(() => (flow.value ? shortFlowId(flow.value.id) : ''))
const tone = computed(() => (flow.value ? verdictTone(flow.value) : 'ok'))
const vColor = computed(() => (tone.value === 'ok' ? 'var(--ok)' : tone.value === 'obs' ? 'var(--obs)' : 'var(--ko)'))
const vBg = computed(() => (tone.value === 'ok' ? 'var(--ok-bg)' : tone.value === 'obs' ? 'var(--obs-bg)' : 'var(--ko-bg)'))
const vKey = computed(() => (tone.value === 'ok' ? 'allow' : tone.value === 'obs' ? 'observed' : 'deny'))
const denied = computed(() => flow.value?.verdict === 'deny')
// The baseline applies before every zone: a flow it denies cannot be allowed from the log.
const baselineLocked = computed(() => denied.value && flow.value?.decision.layer === 'baseline')
const proposal = computed(() => (baselineLocked.value ? null : props.detail?.allow_proposal ?? null))
const http = computed(() => props.detail?.http[0] ?? null)
const httpPath = computed(() => {
  if (!http.value) return ''
  try {
    const u = new URL(http.value.url)
    return `${u.pathname}${u.search}`
  }
  catch {
    return http.value.url
  }
})
const reqBody = computed(() => (http.value?.request_body ? bodyView(http.value.request_body) : null))
const respBody = computed(() => (http.value?.response_body ? bodyView(http.value.response_body) : null))
const dst = computed(() => (flow.value ? splitSocket(flow.value.dst) : { host: '', port: '' }))
const proto = computed(() => (flow.value?.app ?? flow.value?.protocol ?? '').toString())
const correlation = computed(() => props.detail?.correlation ?? null)
const toolCall = computed(() => props.detail?.tool_call ?? null)

const tabs = computed(() => [
  { label: http.value ? t('flow.tab.http') : t('flow.tab.flow'), value: 'http' },
  { label: t('flow.tab.agent'), value: 'agent' },
  { label: t('flow.tab.meta'), value: 'meta' },
])

const protoLabel = computed(() => {
  const f = flow.value
  if (!f) return ''
  const parts = [proto.value.toUpperCase()]
  if (f.tls_inspected) parts.push(t('flow.decrypted'))
  else if (f.app === 'ssh' || f.app === 'other') parts.push(t('flow.notDecrypted'))
  if (f.internal) parts.push(t('flow.internal'))
  if (f.llm_provider) parts.push(t('flow.llmProvider'))
  return parts.join(' · ')
})

const duration = computed(() => {
  const f = flow.value
  if (!f?.ended_at) return null
  return new Date(f.ended_at).getTime() - new Date(f.started_at).getTime()
})

/** EF-21: the exact text received by the agent, given by the API (else a refused connection). */
const agentMessage = computed(() => {
  if (!flow.value || !denied.value) return null
  return props.detail?.agent_message ?? t('flow.connRefused', { rule: ruleLabel.value })
})

const statusLine = computed(() => {
  if (!flow.value) return ''
  if (http.value?.status != null) return httpReason(http.value.status)
  if (denied.value) return t('flow.rst')
  return t('flow.closed')
})

const curl = computed(() => (http.value ? curlFor({ method: http.value.method, url: http.value.url, headers: http.value.request_headers.map(([k, v]) => [k ?? '', v ?? ''] as [string, string]) }) : null))

/** Choices offered by the API, plus the zone's "allowed from the log" group (`group`). */
const options = computed(() => {
  const p = proposal.value
  if (!p) return []
  const out: { key: AllowDestination, label: string, broadening: boolean }[] = p.destinations
    .filter(d => d.kind !== 'existing')
    .map(d => ({ key: d.kind as AllowDestination, label: d.label, broadening: d.kind === 'wildcard' }))
  const exact = p.destinations.find(d => d.kind === 'exact')
  if (exact) out.push({ key: 'group', label: t('allow.groupName', { zone: p.zone_name ?? '' }), broadening: false })
  return out
})
const existing = computed(() => proposal.value?.destinations.filter(d => d.kind === 'existing') ?? [])
const chosen = computed(() => options.value.find(o => o.key === destKey.value) ?? options.value[0])
const zoneAgents = computed(() => dir.zoneAgents(proposal.value?.zone_id).map(a => a.name))
const zoneGateways = computed(() => [...new Set(dir.zoneAgents(proposal.value?.zone_id).map(a => dir.gatewayName(a.gateway_id)).filter((n): n is string => !!n))])
const cli = computed(() => {
  const p = proposal.value
  if (!p || !chosen.value) return ''
  return allowRuleCli({ zone: p.zone_name ?? p.zone_id, dest: chosen.value.label, createObject: true, service: p.service.label, before: String(p.rule_number ?? ''), expiresInDays: expiry.value, flowId: fid.value })
})
const addedDestinations = computed(() => added.value?.destinations.map(id => dir.objectName(id) ?? id).join(', ') ?? '')

const expiries: { key: string, days: number | null }[] = [
  { key: 'none', days: null },
  { key: '7', days: 7 },
  { key: '30', days: 30 },
  { key: '90', days: 90 },
]
const trackItems = computed(() => (['detailed', 'log', 'capture', 'none'] as Track[]).map(v => ({ label: t(`track.${v}Long`), value: v })))

function openAllow() {
  if (!proposal.value) return
  mode.value = 'allow'
}

async function addToSession() {
  const f = flow.value
  const p = proposal.value
  if (!f || !p || busy.value) return
  busy.value = true
  try {
    const s = await ensureOpen(t('allow.sessionName', { dest: f.domain ?? dst.value.host }))
    const res = await api.allowFromLog(s.id, { flow_id: f.id, destination: chosen.value?.key ?? 'exact', expires_in_days: expiry.value, track: track.value })
    added.value = res.rule
    mode.value = 'added'
    await refreshSession()
    await dir.refresh()
    emit('added', res.rule)
  }
  catch (e) {
    problem.notify(e, t('allow.failed'))
  }
  finally {
    busy.value = false
  }
}

async function capture() {
  const f = flow.value
  if (!f?.agent_id) return
  try {
    await api.startCapture({ agent_id: f.agent_id, duration_secs: 300 })
    toast.add({ title: t('flow.captureStarted', { agent: agentName.value }), icon: 'i-lucide-radio' })
  }
  catch (e) {
    problem.notify(e)
  }
}

function copyCurl() {
  if (curl.value) void copy(curl.value, 'curl')
}

defineShortcuts({
  a: () => openAllow(),
  c: () => copyCurl(),
  escape: () => {
    if (mode.value !== 'tabs') mode.value = 'tabs'
  },
  meta_enter: {
    usingInput: true,
    handler: () => {
      if (mode.value === 'allow') void addToSession()
    },
  },
})

defineExpose({ openAllow, copyCurl })

const rulesLink = computed(() => ({ path: '/rules', query: flow.value?.zone_id ? { zone: flow.value.zone_id } : {} }))
</script>

<template>
  <aside
    :aria-label="t('flow.aria')"
    class="afw-card flex min-w-0 flex-col overflow-hidden"
    data-testid="flow-detail"
  >
    <div
      v-if="!flow"
      class="p-6 text-center text-text3"
    >
      {{ loading ? t('common.loading') : t('flow.none') }}
    </div>
    <template v-else>
      <div class="flex flex-col gap-[10px] border-b border-line px-4 pt-[14px] pb-3">
        <div class="flex items-center gap-2 font-mono text-[11.5px] text-text3">
          <span
            class="inline-flex h-[22px] items-center rounded-[5px] px-2 font-bold tracking-[.04em]"
            :style="{ color: vColor, background: vBg }"
          >{{ t(`verdict.${vKey}Upper`) }}</span>
          <span>{{ fmt.time(flow.started_at, true) }}</span>
          <span class="flex-1" />
          <NuxtLink
            v-if="!standalone"
            :to="`/flows/${flow.id}`"
            class="afw-ghost flex h-[22px] items-center rounded-[5px] px-1.5 text-[11px] no-underline"
            style="color: var(--text3)"
            :title="t('flow.openFull')"
          >
            <UIcon
              name="i-lucide-maximize-2"
              class="size-[11px]"
            />
          </NuxtLink>
          <button
            type="button"
            class="afw-ghost flex h-[22px] items-center gap-1.5 rounded-[5px] px-1.5 font-mono text-[11px] text-text3"
            :aria-label="t('flow.copyId')"
            @click="copy(flow.id, fid)"
          >
            {{ fid }}
            <UIcon
              name="i-lucide-copy"
              class="size-[11px]"
            />
          </button>
        </div>
        <div class="flex flex-col gap-[3px]">
          <h2 class="m-0 break-all font-mono text-lg font-semibold tracking-[-.01em]">
            {{ flow.domain ?? dst.host }}
          </h2>
          <span class="font-mono text-xs text-text2">
            <NuxtLink
              :to="`/agents/${flow.agent_id}`"
              class="font-semibold no-underline"
              style="color: var(--text)"
            >{{ agentName }}</NuxtLink><span class="text-text3">@{{ zoneName }}</span>
            → {{ flow.domain ?? dst.host }}:{{ dst.port }} · {{ proto }} · ↑ {{ fmt.bytes(flow.bytes_out) }} ↓ {{ fmt.bytes(flow.bytes_in) }}
          </span>
        </div>

        <div class="flex flex-col overflow-hidden rounded-lg border border-line bg-code">
          <div class="flex items-center justify-between border-b border-line px-[10px] py-[7px]">
            <span class="text-xs font-semibold">{{ t('flow.why') }}</span>
            <span class="font-mono text-[10.5px] text-text3">{{ t('flow.topDown') }}</span>
          </div>
          <FlowTrace
            :steps="detail!.trace"
            :verdict="flow.verdict"
            :observed="flow.observed"
          />
          <div
            v-if="agentMessage"
            class="border-t border-line px-[10px] py-[7px] font-mono text-[11px] text-text2"
          >
            <span class="text-text3">{{ t('flow.receivedByAgent') }}</span> {{ agentMessage }}
          </div>
        </div>

        <div class="flex flex-wrap gap-2">
          <UButton
            v-if="proposal"
            data-testid="allow-open"
            class="h-[34px] rounded-lg bg-pri pr-3 pl-[14px] font-[650] text-pri-fg hover:bg-pri/90"
            icon="i-lucide-plus"
            @click="openAllow"
          >
            {{ t('flow.allow') }}
            <kbd class="rounded border border-current px-1 font-mono text-[10.5px] opacity-70">A</kbd>
          </UButton>
          <span
            v-if="baselineLocked"
            class="flex h-[34px] items-center gap-[7px] rounded-lg bg-obs-bg px-3 text-xs font-semibold text-obs"
          >
            <UIcon
              name="i-lucide-lock"
              class="size-[13px]"
            />{{ t('flow.baselineLocked') }}
          </span>
          <button
            v-if="curl"
            type="button"
            class="afw-ghost flex h-[34px] items-center gap-[7px] rounded-lg !border-line2 px-3 font-medium"
            @click="copyCurl"
          >
            <UIcon
              name="i-lucide-code"
              class="size-[13px]"
            />curl
          </button>
          <button
            type="button"
            class="afw-ghost h-[34px] rounded-lg !border-line2 px-3 font-medium"
            @click="capture"
          >
            {{ t('flow.pcap') }}
          </button>
          <NuxtLink
            :to="rulesLink"
            class="afw-ghost flex h-[34px] items-center rounded-lg !border-line2 px-3 font-medium no-underline"
            style="color: var(--text)"
          >
            {{ t('flow.ruleLink', { n: ruleLabel }) }}
          </NuxtLink>
        </div>
      </div>

      <!-- Allow from the log: pre-filled rule (EF-42) -->
      <div
        v-if="mode === 'allow' && proposal"
        class="flex flex-col gap-3 px-4 pt-[14px] pb-4"
        data-testid="allow-form"
      >
        <div class="flex items-baseline justify-between gap-2">
          <h3 class="m-0 text-sm font-[650]">
            {{ t('allow.title') }}
          </h3>
          <span class="font-mono text-[10.5px] text-text3">{{ t('allow.notApplied') }}</span>
        </div>
        <div class="grid grid-cols-[92px_minmax(0,1fr)] items-center gap-x-3 gap-y-[10px] text-[12.5px]">
          <span class="text-text3">{{ t('allow.source') }}</span>
          <span class="flex flex-wrap items-center gap-2">
            <span class="rounded-[5px] bg-sub px-[7px] py-px font-mono font-semibold">@{{ proposal.zone_name }}</span>
            <span class="text-[11.5px] text-text3">{{ t('allow.sourceNote') }}</span>
          </span>
          <span class="self-start pt-1.5 text-text3">{{ t('allow.destination') }}</span>
          <div
            class="flex flex-col gap-1.5"
            role="radiogroup"
            :aria-label="t('allow.destination')"
          >
            <button
              v-for="o in options"
              :key="o.key"
              type="button"
              role="radio"
              :aria-checked="destKey === o.key"
              class="flex flex-col gap-px rounded-lg border px-[10px] py-[7px] text-left"
              :class="destKey === o.key ? 'border-pri bg-pri-bg' : 'border-line2 bg-transparent'"
              :data-testid="`allow-dest-${o.key}`"
              @click="destKey = o.key"
            >
              <span class="flex items-center gap-2">
                <span
                  class="flex size-3 flex-none items-center justify-center rounded-full border-[1.5px]"
                  :class="destKey === o.key ? 'border-pri' : 'border-line2'"
                >
                  <span
                    class="size-1.5 rounded-full"
                    :class="destKey === o.key ? 'bg-pri' : 'bg-transparent'"
                  />
                </span>
                <span class="font-mono text-xs font-semibold">{{ o.label }}</span>
                <span class="text-[11.5px] text-text3">{{ t(`allow.option.${o.key}`) }}</span>
              </span>
              <span
                v-if="o.broadening && destKey === o.key"
                class="pl-5 text-[11px] text-warn"
              >{{ t('allow.broadening') }}</span>
            </button>
            <span
              v-for="x in existing"
              :key="x.object_id ?? x.label"
              class="text-[11.5px] text-text3"
            >{{ t('allow.existing', { name: x.label }) }}</span>
          </div>
          <span class="text-text3">{{ t('allow.expiry') }}</span>
          <div
            role="group"
            :aria-label="t('allow.expiry')"
            class="flex flex-wrap gap-1"
          >
            <button
              v-for="e in expiries"
              :key="e.key"
              type="button"
              class="h-[26px] rounded-md border px-[9px] font-mono text-[11.5px] font-semibold"
              :class="expiry === e.days ? 'border-pri bg-pri-bg text-pri' : 'border-line2 bg-transparent text-text2'"
              :aria-pressed="expiry === e.days"
              @click="expiry = e.days"
            >
              {{ e.days === null ? t('allow.noExpiry') : t('allow.days', { n: e.days }) }}
            </button>
          </div>
          <label
            for="afw-track"
            class="text-text3"
          >{{ t('allow.track') }}</label>
          <USelect
            id="afw-track"
            v-model="track"
            :items="trackItems"
            size="sm"
            class="w-full"
          />
        </div>

        <CliSnippet
          :label="t('allow.cliLabel')"
          :code="cli"
        />

        <div class="flex flex-col gap-[3px] rounded-lg border border-dashed border-line2 px-[11px] py-[9px] text-xs">
          <span>{{ t('allow.service', { service: proposal.service.label, port: proposal.service.port }) }}<template v-if="proposal.rule_number"> · {{ t('allow.position', { n: proposal.rule_number }) }}</template></span>
          <span class="text-text2">{{ t('allow.appliesToZone', { zone: proposal.zone_name ?? '' }) }} {{ zoneAgents.join(', ') || '—' }}.</span>
        </div>
        <div class="flex justify-end gap-2">
          <button
            type="button"
            class="afw-ghost h-[34px] rounded-lg !border-line2 px-[14px] font-medium"
            @click="mode = 'tabs'"
          >
            {{ t('common.cancel') }} <span class="font-mono text-[10.5px] text-text3">esc</span>
          </button>
          <UButton
            data-testid="allow-submit"
            :loading="busy"
            class="h-[34px] rounded-lg bg-pri px-[14px] font-[650] text-pri-fg hover:bg-pri/90"
            @click="addToSession"
          >
            {{ t('allow.addToSession') }} <span class="font-mono text-[10.5px] opacity-70">⌘↵</span>
          </UButton>
        </div>
      </div>

      <!-- Rule added to the session -->
      <div
        v-else-if="mode === 'added' && added && proposal"
        class="flex flex-col gap-[14px] px-4 py-[18px]"
        data-testid="allow-added"
      >
        <div class="flex items-center gap-[10px]">
          <span class="flex size-[30px] items-center justify-center rounded-lg bg-ok-bg text-ok">
            <UIcon
              name="i-lucide-check"
              class="size-4"
            />
          </span>
          <div class="flex flex-col">
            <strong class="text-sm">{{ t('allow.added', { n: added.number }) }}</strong>
            <span class="font-mono text-[11.5px] text-text2">@{{ proposal.zone_name }} → {{ addedDestinations }} · {{ proposal.service.label }} · {{ expiry === null ? t('allow.noExpiryLong') : t('allow.expiresIn', { n: expiry }) }}</span>
          </div>
        </div>
        <ol class="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px]">
          <li class="flex items-center gap-2">
            <span class="flex size-[18px] items-center justify-center rounded-full bg-ok text-[10px] font-bold text-pri-fg">✓</span>{{ t('steps.modify') }}
          </li>
          <li class="flex items-center gap-2">
            <span class="flex size-[18px] items-center justify-center rounded-full border-[1.5px] border-pri text-[10px] font-bold text-pri">2</span>{{ t('steps.publish') }}<template v-if="nextRevision">
              · {{ t('steps.revision', { n: nextRevision }) }}
            </template>
          </li>
          <li class="flex items-center gap-2 text-text3">
            <span class="flex size-[18px] items-center justify-center rounded-full border-[1.5px] border-line2 text-[10px] font-bold">3</span>{{ t('steps.install') }}<template v-if="zoneGateways.length">
              · {{ zoneGateways.join(', ') }}
            </template>
          </li>
        </ol>
        <div class="flex flex-wrap gap-2">
          <NuxtLink
            :to="{ path: '/rules', query: { zone: proposal.zone_id } }"
            class="flex h-[34px] items-center gap-[7px] rounded-lg bg-pri px-[14px] font-[650] text-pri-fg no-underline hover:text-pri-fg"
            data-testid="allow-review"
          >
            {{ t('allow.review') }}
            <UIcon
              name="i-lucide-arrow-right"
              class="size-[14px]"
            />
          </NuxtLink>
          <button
            type="button"
            class="afw-ghost h-[34px] rounded-lg !border-line2 px-3 font-medium"
            @click="mode = 'tabs'"
          >
            {{ t('allow.back') }}
          </button>
        </div>
      </div>

      <template v-else>
        <UTabs
          v-model="tab"
          :items="tabs"
          variant="link"
          :content="false"
          size="sm"
          class="px-3"
          :ui="{ list: 'border-line', trigger: 'text-[12.5px] font-semibold' }"
        />

        <div
          v-if="tab === 'http'"
          class="flex flex-col gap-[10px] px-4 py-3"
        >
          <div class="overflow-hidden rounded-lg border border-line bg-code font-mono text-[11.5px] leading-[1.6]">
            <div class="flex justify-between border-b border-line px-[10px] py-1.5 text-[10.5px] text-text3">
              <span>{{ t('flow.request') }} · {{ proto }}</span><span>↑ {{ fmt.bytes(flow.bytes_out) }}</span>
            </div>
            <template v-if="http">
              <div class="break-all px-[10px] pt-2 pb-0.5">
                <span class="font-semibold text-pri">{{ http.method }}</span> <span>{{ httpPath }}</span> <span class="text-text3">HTTP/1.1</span>
              </div>
              <div class="flex flex-col px-[10px] pb-2">
                <span
                  v-for="([k, v], i) in http.request_headers"
                  :key="i"
                  class="break-all"
                ><span class="text-syn-key">{{ k }}:</span> <span :class="v?.startsWith('[secret:') ? 'text-obs' : k?.toLowerCase().startsWith('x-afw') ? 'text-text2' : ''">{{ v }}</span></span>
              </div>
              <pre
                v-if="reqBody"
                class="m-0 whitespace-pre-wrap break-all border-t border-dashed border-line2 px-[10px] py-2 font-mono text-syn-str"
                data-testid="request-body"
              >{{ reqBody.kind === 'text' ? reqBody.text : t('flow.binary', { size: fmt.bytes(reqBody.size) }) }}</pre>
              <div
                v-if="reqBody?.truncated"
                class="border-t border-dashed border-line2 px-[10px] py-1 text-[10.5px] text-warn"
              >
                {{ t('flow.truncated', { size: fmt.bytes(reqBody.size) }) }}
              </div>
            </template>
            <template v-else>
              <div class="flex flex-col px-[10px] py-2">
                <span class="break-all"><span class="text-syn-key">{{ t('flow.flowKey') }}:</span> {{ flow.src }} → {{ flow.dst }}</span>
                <span><span class="text-syn-key">{{ t('flow.inspectionKey') }}:</span> <span class="text-text2">{{ t('flow.inspectionImpossible', { proto: proto.toUpperCase() }) }}</span></span>
              </div>
              <pre class="m-0 whitespace-pre-wrap border-t border-dashed border-line2 px-[10px] py-2 font-mono text-syn-str">{{ t('flow.metadataOnly', { proto: proto.toUpperCase() }) }}</pre>
            </template>
          </div>
          <div class="overflow-hidden rounded-lg border border-line bg-code font-mono text-[11.5px] leading-[1.6]">
            <div class="flex justify-between border-b border-line px-[10px] py-1.5 text-[10.5px] text-text3">
              <span>{{ t('flow.response') }}</span><span>{{ fmt.duration(duration) }}</span>
            </div>
            <div class="px-[10px] pt-2 pb-0.5">
              <span
                class="font-bold"
                :style="{ color: denied ? 'var(--ko)' : 'var(--ok)' }"
              >{{ statusLine }}</span>
            </div>
            <div
              v-if="http?.response_headers.length"
              class="flex flex-col px-[10px] pb-1"
            >
              <span
                v-for="([k, v], i) in http.response_headers"
                :key="i"
                class="break-all"
              ><span class="text-syn-key">{{ k }}:</span> <span :class="v?.startsWith('[secret:') ? 'text-obs' : ''">{{ v }}</span></span>
            </div>
            <pre class="m-0 whitespace-pre-wrap break-all px-[10px] pb-2 font-mono text-text2">{{ respBody ? (respBody.kind === 'text' ? respBody.text : t('flow.binary', { size: fmt.bytes(respBody.size) })) : '' }}</pre>
            <div
              v-if="respBody?.truncated"
              class="px-[10px] pb-1 text-[10.5px] text-warn"
            >
              {{ t('flow.truncated', { size: fmt.bytes(respBody.size) }) }}
            </div>
          </div>
          <span class="flex items-center gap-1.5 text-[11px] text-text3">
            <UIcon
              name="i-lucide-lock"
              class="size-3"
            />{{ t('flow.maskedNote') }}
          </span>
        </div>

        <div
          v-else-if="tab === 'agent'"
          class="flex flex-col gap-3 px-4 py-[14px]"
        >
          <template v-if="correlation || toolCall">
            <div
              v-if="correlation"
              class="flex flex-wrap items-center gap-2"
            >
              <span
                class="rounded-[5px] px-[7px] py-px font-mono text-[11px] font-semibold"
                :class="correlation.confidence === 'certain' ? 'bg-ok-bg text-ok' : 'bg-warn-bg text-warn'"
              >{{ t(`flow.attrib.${correlation.confidence}`) }}</span>
              <span class="text-[11.5px] text-text3">{{ t(`flow.attribHow.${correlation.confidence}`) }}</span>
            </div>
            <div class="flex items-baseline justify-between gap-2">
              <strong class="font-mono text-[13px]">{{ t('flow.conversation', { id: correlation?.conversation_id ?? toolCall?.conversation_id ?? '' }) }}</strong>
              <NuxtLink
                :to="`/agents/${flow.agent_id}`"
                class="whitespace-nowrap text-xs"
              >{{ t('flow.fullConversation') }}</NuxtLink>
            </div>
            <ol class="m-0 flex list-none flex-col p-0 pl-1">
              <li
                v-if="toolCall"
                class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]"
              >
                <span class="flex flex-col items-center"><span class="mt-1 size-[9px] rounded-full border-2 border-pri" /><span class="w-px flex-1 bg-line2" /></span>
                <span class="flex flex-col gap-1 pb-3"><span class="font-mono text-[10.5px] text-pri">{{ t('flow.toolCall') }} · {{ fmt.time(toolCall.started_at, true) }}<template v-if="toolCall.status"> · {{ toolCall.status }}</template></span><code class="rounded-md border border-line bg-code px-2 py-[5px] font-mono text-xs">{{ toolCall.tool }}({{ toolCall.args_summary }})</code></span>
              </li>
              <li class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]">
                <span class="flex flex-col items-center"><span
                  class="mt-1 size-[9px] rounded-full"
                  :style="{ background: vColor }"
                /></span>
                <span class="flex flex-col gap-0.5"><span
                  class="font-mono text-[10.5px]"
                  :style="{ color: vColor }"
                >{{ t('flow.network', { gw: gatewayName }) }}</span><span class="text-[12.5px] font-semibold">{{ t(denied ? 'flow.effectDenied' : 'flow.effectAllowed', { dest: flow.domain ?? dst.host, size: fmt.bytes(flow.bytes_out), rule: ruleLabel }) }}</span></span>
              </li>
            </ol>
          </template>
          <span
            v-else
            class="text-text3"
          >{{ t('flow.noCorrelation') }}</span>
        </div>

        <dl
          v-else
          class="m-0 grid grid-cols-[116px_minmax(0,1fr)] gap-x-3 gap-y-[7px] px-4 py-[14px] text-[12.5px]"
        >
          <dt class="text-text3">
            {{ t('flow.meta.gateway') }}
          </dt><dd class="m-0 font-mono text-xs">
            {{ gatewayName }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.addresses') }}
          </dt><dd class="m-0 break-all font-mono text-xs">
            {{ flow.src }} → {{ flow.dst }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.protocol') }}
          </dt><dd class="m-0">
            {{ protoLabel }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.volumes') }}
          </dt><dd class="m-0 font-mono text-xs">
            ↑ {{ fmt.bytes(flow.bytes_out) }} · ↓ {{ fmt.bytes(flow.bytes_in) }} · {{ fmt.duration(duration) }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.dataClass') }}
          </dt><dd class="m-0">
            {{ flow.data_classes.join(', ') || '—' }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.conversation') }}
          </dt><dd class="m-0">
            {{ correlation?.conversation_id ?? '—' }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.rule') }}
          </dt><dd class="m-0">
            {{ ruleLabel }}<template v-if="flow.decision.revision != null"> · {{ t('flow.meta.revision', { n: flow.decision.revision }) }}</template>
          </dd>
        </dl>

        <div class="mt-auto flex items-center gap-2 border-t border-line bg-code px-4 py-[9px] font-mono text-[11.5px]">
          <span class="text-text3">$</span>
          <span class="min-w-0 flex-1 truncate">afw flow show {{ fid }} --body</span>
          <button
            type="button"
            class="afw-ghost rounded px-1.5 font-mono text-[10.5px] text-text2"
            @click="copy(`afw flow show ${fid} --body`)"
          >
            {{ t('common.copy') }}
          </button>
        </div>
      </template>
    </template>
  </aside>
</template>
