<script setup lang="ts">
import type { DestinationOption, FlowDetail, RuleView, Track, ZoneView } from '~/api/types'
import { allowRuleCli, curlFor, httpReason } from '~/utils/cli'
import { isBaselineLabel, shortFlowId, splitSocket, verdictTone } from '~/utils/format'

const props = defineProps<{
  detail: FlowDetail | null
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
const { ensureOpen, refresh: refreshSession } = usePolicySession()

type Mode = 'tabs' | 'allow' | 'added'
const mode = ref<Mode>('tabs')
const tab = ref<'http' | 'agent' | 'meta'>('http')
const destKey = ref<DestinationOption['key']>('exact')
const expiry = ref<number | null>(30)
const track = ref<Track>('detailed')
const busy = ref(false)
const added = ref<RuleView | null>(null)
const nextRevision = ref<number | null>(null)
const zoneGateways = ref<string[]>([])

watch(() => props.detail?.flow.id, () => {
  mode.value = 'tabs'
  destKey.value = 'exact'
  expiry.value = 30
  track.value = 'detailed'
  added.value = null
})

const flow = computed(() => props.detail?.flow ?? null)
const fid = computed(() => (flow.value ? shortFlowId(flow.value.id) : ''))
const tone = computed(() => (flow.value ? verdictTone(flow.value) : 'ok'))
const vColor = computed(() => (tone.value === 'ok' ? 'var(--ok)' : tone.value === 'obs' ? 'var(--obs)' : 'var(--ko)'))
const vBg = computed(() => (tone.value === 'ok' ? 'var(--ok-bg)' : tone.value === 'obs' ? 'var(--obs-bg)' : 'var(--ko-bg)'))
const vKey = computed(() => (tone.value === 'ok' ? 'allow' : tone.value === 'obs' ? 'observed' : 'deny'))
const denied = computed(() => flow.value?.verdict === 'deny')
const baselineLocked = computed(() => denied.value && !!flow.value && isBaselineLabel(flow.value.rule_label))
const proposal = computed(() => props.detail?.allow_proposal ?? null)
const http = computed(() => props.detail?.http ?? null)
const dst = computed(() => (flow.value ? splitSocket(flow.value.dst) : { host: '', port: '' }))
const proto = computed(() => (flow.value?.app ?? flow.value?.protocol ?? '').toString())

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

const agentMessage = computed(() => {
  const f = flow.value
  if (!f || !denied.value) return null
  return props.detail?.agent_message
    ? t('flow.agentMessage', { dest: f.domain ?? dst.value.host, agent: f.agent_name ?? '', rule: f.rule_label })
    : t('flow.connRefused', { rule: f.rule_label })
})

const statusLine = computed(() => {
  const f = flow.value
  if (!f) return ''
  if (http.value?.status != null) {
    const base = httpReason(http.value.status)
    return denied.value ? `${base} · X-AFW-Rule: ${f.rule_label}` : base
  }
  if (denied.value) return t('flow.rst')
  return t('flow.closed')
})

const curl = computed(() => (http.value ? curlFor({ method: http.value.method, url: http.value.url, headers: http.value.request_headers }) : null))

const options = computed(() => proposal.value?.destination_options ?? [])
const chosen = computed(() => options.value.find(o => o.key === destKey.value) ?? options.value[0])
const cli = computed(() => {
  const p = proposal.value
  if (!p || !chosen.value) return ''
  return allowRuleCli({ zone: p.zone.name, dest: chosen.value.value, createObject: chosen.value.object_id === null, service: p.service, before: p.before_rule, expiresInDays: expiry.value, flowId: fid.value })
})

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
  void (async () => {
    const [revs, zones] = await Promise.all([api.listRevisions(), api.listZones()])
    nextRevision.value = (revs[0]?.number ?? 0) + 1
    zoneGateways.value = zones.find((z: ZoneView) => z.id === proposal.value?.zone.id)?.gateways ?? []
  })()
}

async function addToSession() {
  const f = flow.value
  const p = proposal.value
  if (!f || !p || busy.value) return
  busy.value = true
  try {
    const session = await ensureOpen(t('allow.sessionName', { dest: f.domain ?? dst.value.host }))
    const res = await api.allowFromLog(session.id, { flow_id: f.id, destination: destKey.value, expires_in_days: expiry.value, track: track.value })
    added.value = res.rule
    mode.value = 'added'
    await refreshSession()
    emit('added', res.rule)
  }
  catch (e) {
    toast.add({ title: t('allow.failed'), description: e instanceof Error ? e.message : String(e), color: 'error' })
  }
  finally {
    busy.value = false
  }
}

async function capture() {
  const f = flow.value
  if (!f?.agent_id) return
  await api.startCapture({ agent_id: f.agent_id, duration_secs: 300 })
  toast.add({ title: t('flow.captureStarted', { agent: f.agent_name ?? '' }), icon: 'i-lucide-radio' })
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
            >{{ flow.agent_name }}</NuxtLink><span class="text-text3">@{{ flow.zone_name }}</span>
            → {{ flow.domain ?? dst.host }}:{{ dst.port }} · {{ proto }} · ↑ {{ fmt.bytes(flow.bytes_out) }} ↓ {{ fmt.bytes(flow.bytes_in) }}
          </span>
        </div>

        <div class="flex flex-col overflow-hidden rounded-lg border border-line bg-code">
          <div class="flex items-center justify-between border-b border-line px-[10px] py-[7px]">
            <span class="text-xs font-semibold">{{ t('flow.why') }}</span>
            <span class="font-mono text-[10.5px] text-text3">{{ t('flow.topDown') }}</span>
          </div>
          <FlowTrace :steps="detail!.trace" />
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
            {{ t('flow.ruleLink', { n: flow.rule_label }) }}
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
            <span class="rounded-[5px] bg-sub px-[7px] py-px font-mono font-semibold">@{{ proposal.zone.name }}</span>
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
                <span class="font-mono text-xs font-semibold">{{ o.value }}</span>
                <span class="text-[11.5px] text-text3">{{ t(`allow.option.${o.key}`, { n: o.members ?? 0 }) }}<template v-if="o.key === 'exact' && o.object_id === null"> · {{ t('allow.newObject') }}</template></span>
              </span>
              <span
                v-if="o.broadening && destKey === o.key"
                class="pl-5 text-[11px] text-warn"
              >{{ t('allow.broadening') }}</span>
            </button>
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
          <i18n-t
            keypath="allow.wouldAllow"
            scope="global"
            tag="span"
          >
            <template #n>
              <strong>{{ t('allow.wouldAllowN', { n: proposal.would_allow.flows, agents: proposal.would_allow.agents.join(', ') }) }}</strong>
            </template>
          </i18n-t>
          <span class="text-text2">{{ t('allow.appliesToZone', { zone: proposal.zone.name }) }} {{ proposal.zone_agents.join(', ') }}.</span>
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
            <span class="font-mono text-[11.5px] text-text2">@{{ proposal.zone.name }} → {{ added.destination_names.join(', ') }} · {{ proposal.service }} · {{ expiry === null ? t('allow.noExpiryLong') : t('allow.expiresIn', { n: expiry }) }}</span>
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
            :to="{ path: '/rules', query: { zone: proposal.zone.id } }"
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
                <span class="font-semibold text-pri">{{ http.method }}</span> <span>{{ flow.path }}</span> <span class="text-text3">HTTP/1.1</span>
              </div>
              <div class="flex flex-col px-[10px] pb-2">
                <span
                  v-for="[k, v] in http.request_headers"
                  :key="k"
                  class="break-all"
                ><span class="text-syn-key">{{ k }}:</span> <span :class="v.startsWith('[secret:') ? 'text-obs' : k.startsWith('X-AFW') ? 'text-text2' : ''">{{ v }}</span></span>
              </div>
              <pre
                v-if="http.request_body"
                class="m-0 whitespace-pre-wrap break-all border-t border-dashed border-line2 px-[10px] py-2 font-mono text-syn-str"
              >{{ http.request_body.data }}</pre>
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
            <pre class="m-0 whitespace-pre-wrap break-all px-[10px] pb-2 font-mono text-text2">{{ http?.response_body?.data ?? '' }}</pre>
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
          <template v-if="flow.correlation">
            <div class="flex flex-wrap items-center gap-2">
              <span
                class="rounded-[5px] px-[7px] py-px font-mono text-[11px] font-semibold"
                :class="flow.correlation.confidence === 'certain' ? 'bg-ok-bg text-ok' : 'bg-warn-bg text-warn'"
              >{{ t(`flow.attrib.${flow.correlation.confidence}`) }}</span>
              <span class="text-[11.5px] text-text3">{{ t(`flow.attribHow.${flow.correlation.confidence}`) }}</span>
            </div>
            <div class="flex items-baseline justify-between gap-2">
              <strong class="text-[13px]">{{ flow.correlation.conversation_title }}</strong>
              <NuxtLink
                :to="`/agents/${flow.agent_id}`"
                class="whitespace-nowrap text-xs"
              >{{ t('flow.fullConversation') }}</NuxtLink>
            </div>
            <ol class="m-0 flex list-none flex-col p-0 pl-1">
              <li class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]">
                <span class="flex flex-col items-center"><span class="mt-1 size-[9px] rounded-full border-2 border-warn" /><span class="w-px flex-1 bg-line2" /></span>
                <span class="flex flex-col gap-0.5 pb-3"><span class="font-mono text-[10.5px] text-warn">{{ t('flow.untrusted', { source: flow.correlation.trigger_source ?? '' }) }}</span><span class="text-[12.5px]">{{ flow.correlation.trigger_text }}</span></span>
              </li>
              <li class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]">
                <span class="flex flex-col items-center"><span class="mt-1 size-[9px] rounded-full border-2 border-text3" /><span class="w-px flex-1 bg-line2" /></span>
                <span class="flex flex-col gap-0.5 pb-3"><span class="font-mono text-[10.5px] text-text3">{{ t('flow.reasoning', { agent: flow.agent_name ?? '' }) }}</span><span class="text-[12.5px] text-text2">{{ flow.correlation.reasoning }}</span></span>
              </li>
              <li class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]">
                <span class="flex flex-col items-center"><span class="mt-1 size-[9px] rounded-full border-2 border-pri" /><span class="w-px flex-1 bg-line2" /></span>
                <span class="flex flex-col gap-1 pb-3"><span class="font-mono text-[10.5px] text-pri">{{ t('flow.toolCall') }}</span><code class="rounded-md border border-line bg-code px-2 py-[5px] font-mono text-xs">{{ detail!.tool_call?.tool ?? flow.tool }}</code></span>
              </li>
              <li class="grid grid-cols-[14px_minmax(0,1fr)] gap-[10px]">
                <span class="flex flex-col items-center"><span
                  class="mt-1 size-[9px] rounded-full"
                  :style="{ background: vColor }"
                /></span>
                <span class="flex flex-col gap-0.5"><span
                  class="font-mono text-[10.5px]"
                  :style="{ color: vColor }"
                >{{ t('flow.network', { gw: flow.gateway_name }) }}</span><span class="text-[12.5px] font-semibold">{{ t(denied ? 'flow.effectDenied' : 'flow.effectAllowed', { dest: flow.domain ?? dst.host, size: fmt.bytes(flow.bytes_out), rule: flow.rule_label }) }}</span></span>
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
            {{ flow.gateway_name }}
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
            {{ detail!.data_class_label ?? '—' }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.conversation') }}
          </dt><dd class="m-0">
            {{ flow.correlation?.conversation_title ?? '—' }}
          </dd>
          <dt class="text-text3">
            {{ t('flow.meta.rule') }}
          </dt><dd class="m-0">
            #{{ flow.rule_label }} · {{ flow.decision.rule_name }}
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
