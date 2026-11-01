<script setup lang="ts">
import type { FlowDetail, FlowListItem, FlowQuery, FlowStats, FlowStatsQuery, StatsBucket } from '~/api/types'
import type { Segment } from '~/components/flow/FlowHistogram.vue'
import { parseQuery, queryTokens, toFlowQuery, type QueryFilters } from '~/utils/query'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const route = useRoute()
const router = useRouter()
const { refreshShell } = useShell()

useHead({ title: () => `${t('nav.journal')} — agents-firewall` })

const filters = ref<QueryFilters>(parseQuery(String(route.query.q ?? '')))
const segment = ref<Segment>('all')
const period = ref<'15m' | '1h' | '24h' | '7d'>('1h')
const range = ref<{ from: string, to: string } | null>(null)
const input = ref('')
const paused = ref(false)
const searchEl = ref<HTMLInputElement | null>(null)
const paletteOpen = useState('afw-palette', () => false)

const PERIOD_MS = { '15m': 15 * 60_000, '1h': 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000 }
const BUCKET: Record<keyof typeof PERIOD_MS, StatsBucket> = { '15m': '1m', '1h': '1m', '24h': '1h', '7d': '1h' }
const { data: dirData, ensure: ensureDirectory } = useDirectory()
const ruleNumbers = ref<{ id: string, number: number }[]>([])

/** Filters of the query bar (names typed by the user are resolved to the ids the API expects). */
const base = computed<FlowQuery>(() => ({
  ...toFlowQuery(filters.value, { agents: dirData.value.agents, zones: dirData.value.zones, rules: ruleNumbers.value }),
  from: range.value?.from ?? new Date(Date.now() - PERIOD_MS[period.value]).toISOString(),
  to: range.value?.to,
}))
const query = computed<FlowQuery>(() => ({
  ...base.value,
  verdict: segment.value === 'allow' || segment.value === 'observed' ? 'allow' : segment.value === 'deny' ? 'deny' : base.value.verdict,
}))

const allFlows = ref<FlowListItem[]>([])
// "Observed" has no server-side filter: the allowed page is narrowed to the flows allowed only by observation mode.
const flows = computed(() => (segment.value === 'observed' ? allFlows.value.filter(f => f.observed) : segment.value === 'allow' ? allFlows.value.filter(f => !f.observed) : allFlows.value))
const stats = ref<FlowStats | null>(null)
const loading = ref(true)

async function load() {
  loading.value = true
  try {
    await ensureDirectory()
    if (filters.value.rule && !ruleNumbers.value.length) ruleNumbers.value = (await api.listRules()).map(r => ({ id: r.id, number: r.number }))
    const { cursor: _c, limit: _l, ...rest } = base.value
    const statsQuery: FlowStatsQuery = { ...rest, bucket: range.value ? undefined : BUCKET[period.value] }
    const [page, s] = await Promise.all([api.listFlows({ ...query.value, limit: 200 }), api.flowStats(statsQuery)])
    allFlows.value = page.items
    stats.value = s
    if (!selectedId.value || !flows.value.some(f => f.id === selectedId.value)) selectedId.value = flows.value[0]?.id ?? null
  }
  finally {
    loading.value = false
  }
}

const selectedId = ref<string | null>(typeof route.query.flow === 'string' ? route.query.flow : null)
const detail = ref<FlowDetail | null>(null)
const detailLoading = ref(false)
let detailSeq = 0

watch(selectedId, async (id) => {
  if (id !== route.query.flow) void router.replace({ query: { ...route.query, flow: id ?? undefined } })
  if (!id) {
    detail.value = null
    return
  }
  const seq = ++detailSeq
  detailLoading.value = true
  try {
    const d = await api.getFlow(id)
    if (seq === detailSeq) detail.value = d
  }
  finally {
    if (seq === detailSeq) detailLoading.value = false
  }
}, { immediate: true })

watch(query, () => void load(), { deep: true })
const selectedItem = computed(() => allFlows.value.find(f => f.id === selectedId.value) ?? null)
/** Flows of the last complete minute, as counted by the API. */
const perMinute = computed(() => {
  const p = stats.value?.bucket === '1m' ? stats.value.points.at(-2) : undefined
  return p ? p.allow + p.deny + p.observed : 0
})
onMounted(() => void load())

let reloadTimer: ReturnType<typeof setTimeout> | null = null
let unsubscribe: (() => void) | null = null
onMounted(() => {
  unsubscribe = api.streamLogs((e) => {
    if (paused.value) return
    if (e.kind === 'lagged') {
      // Events were skipped by the server: the stream is not trustworthy, reload the page.
      void load()
      return
    }
    if (e.event.type !== 'flow' && e.event.type !== 'alert') return
    if (reloadTimer) return
    reloadTimer = setTimeout(() => {
      reloadTimer = null
      void load()
    }, 400)
  })
})
onBeforeUnmount(() => {
  unsubscribe?.()
  if (reloadTimer) clearTimeout(reloadTimer)
})

const tokens = computed(() => queryTokens(filters.value))
const tokenLabel = (k: string) => t(`query.key.${k}`)
const tokenValue = (k: string, v: string) => (k === 'verdict' ? t(`verdict.${v}`) : v)

function submit() {
  const parsed = parseQuery(input.value)
  if (!Object.keys(parsed).length) return
  filters.value = { ...filters.value, ...parsed, q: [filters.value.q, parsed.q].filter(Boolean).join(' ') || undefined }
  input.value = ''
}

function removeToken(k: keyof QueryFilters) {
  filters.value = Object.fromEntries(Object.entries(filters.value).filter(([key]) => key !== k)) as QueryFilters
}

function onBackspace() {
  if (input.value) return
  const last = tokens.value.at(-1)
  if (last) removeToken(last.key)
  else if (segment.value !== 'all') segment.value = 'all'
}

const periodItems = computed(() => [(['15m', '1h', '24h', '7d'] as const).map(p => ({
  label: t(`journal.period.${p}`),
  onSelect: () => {
    period.value = p
    range.value = null
  },
}))])

const panel = ref<{ openAllow: () => void, copyCurl: () => void } | null>(null)

function move(delta: number) {
  const idx = flows.value.findIndex(f => f.id === selectedId.value)
  const next = flows.value[Math.min(flows.value.length - 1, Math.max(0, idx + delta))]
  if (next) selectedId.value = next.id
}

defineShortcuts({
  'j': () => move(1),
  'k': () => move(-1),
  '/': () => searchEl.value?.focus(),
  'arrowdown': () => move(1),
  'arrowup': () => move(-1),
})

async function onAdded() {
  await refreshShell()
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :prefix="t('journal.prefix')"
      :title="t('nav.journal')"
    >
      <span
        class="inline-flex h-6 items-center gap-[7px] rounded-full border border-line2 px-[9px] font-mono text-[11.5px]"
        :class="paused ? 'text-text3' : 'text-ok'"
      >
        <span
          class="size-[7px] rounded-full"
          :class="paused ? 'bg-text3' : 'afw-live-dot bg-ok'"
        />{{ paused ? t('journal.paused') : t('journal.live', { n: perMinute }) }}
      </span>
      <template #actions>
        <button
          type="button"
          class="afw-ghost hidden h-8 min-w-[280px] items-center gap-[10px] rounded-lg !border-line !bg-bg px-[10px] text-left text-[12.5px] text-text3 lg:flex"
          @click="paletteOpen = true"
        >
          <UIcon
            name="i-lucide-search"
            class="size-[14px]"
          />
          <span class="flex-1">{{ t('palette.goto') }}</span>
          <kbd class="afw-kbd">⌘K</kbd>
        </button>
      </template>
    </ShellPageHeader>

    <div class="flex flex-wrap items-start gap-[14px] px-4 py-[14px]">
      <section
        :aria-label="t('journal.flows')"
        class="flex min-w-0 flex-[999_1_640px] flex-col gap-[10px]"
      >
        <div class="flex flex-wrap items-center gap-2">
          <label class="flex min-h-[38px] flex-[1_1_360px] items-center gap-2 rounded-[9px] border border-line2 bg-panel py-1 pr-1.5 pl-3 font-mono text-[12.5px]">
            <span
              aria-hidden="true"
              class="font-semibold text-pri"
            >›</span>
            <span class="sr-only-afw">{{ t('journal.queryLabel') }}</span>
            <span class="flex min-w-0 flex-1 flex-wrap items-center gap-[5px]">
              <span class="inline-flex h-6 items-center gap-0.5 rounded-md border border-line bg-sub pr-2 pl-2">
                <span class="text-text3">{{ t('query.key.since') }}:</span><span class="font-semibold">{{ range ? `${fmt.hm(range.from)}–${fmt.hm(range.to)}` : t(`journal.period.${period}`) }}</span>
                <button
                  v-if="range"
                  type="button"
                  class="flex size-[18px] items-center justify-center rounded border-0 bg-transparent text-text3"
                  :aria-label="t('journal.removeFilter')"
                  @click="range = null"
                >
                  <UIcon
                    name="i-lucide-x"
                    class="size-[10px]"
                  />
                </button>
              </span>
              <span
                v-if="segment !== 'all'"
                class="inline-flex h-6 items-center gap-0.5 rounded-md border border-line bg-sub pr-1 pl-2"
              >
                <span class="text-text3">{{ t('query.key.verdict') }}:</span>
                <span
                  class="font-semibold"
                  :class="segment === 'allow' ? 'text-ok' : segment === 'deny' ? 'text-ko' : 'text-warn'"
                >{{ t(`journal.segmentToken.${segment}`) }}</span>
                <button
                  type="button"
                  class="flex size-[18px] items-center justify-center rounded border-0 bg-transparent text-text3"
                  :aria-label="t('journal.removeFilter')"
                  @click="segment = 'all'"
                >
                  <UIcon
                    name="i-lucide-x"
                    class="size-[10px]"
                  />
                </button>
              </span>
              <span
                v-for="tk in tokens"
                :key="tk.key"
                class="inline-flex h-6 items-center gap-0.5 rounded-md border border-line bg-sub pr-1 pl-2"
                :data-testid="`token-${tk.key}`"
              >
                <span class="text-text3">{{ tokenLabel(tk.key) }}:</span><span class="font-semibold">{{ tokenValue(tk.key, tk.value) }}</span>
                <button
                  type="button"
                  class="flex size-[18px] items-center justify-center rounded border-0 bg-transparent text-text3"
                  :aria-label="t('journal.removeFilter')"
                  @click="removeToken(tk.key)"
                >
                  <UIcon
                    name="i-lucide-x"
                    class="size-[10px]"
                  />
                </button>
              </span>
              <input
                ref="searchEl"
                v-model="input"
                type="search"
                :placeholder="t('journal.queryPlaceholder')"
                class="min-w-[160px] flex-1 border-0 bg-transparent font-mono text-[12.5px] outline-0"
                data-testid="query-input"
                @keydown.enter.prevent="submit"
                @keydown.backspace="onBackspace"
              >
            </span>
            <kbd class="afw-kbd text-text3">/</kbd>
          </label>
          <UDropdownMenu :items="periodItems">
            <button
              type="button"
              class="afw-ghost flex h-[38px] items-center gap-1.5 rounded-[9px] !border-line2 !bg-panel px-3 font-mono text-xs"
            >
              {{ t(`journal.period.${period}`) }}
              <UIcon
                name="i-lucide-chevron-down"
                class="size-[11px]"
              />
            </button>
          </UDropdownMenu>
          <button
            type="button"
            class="afw-ghost flex h-[38px] items-center gap-[7px] rounded-[9px] !border-line2 !bg-panel px-3 text-[12.5px] font-medium"
            :aria-pressed="paused"
            @click="paused = !paused"
          >
            <UIcon
              :name="paused ? 'i-lucide-play' : 'i-lucide-pause'"
              class="size-3"
            />{{ paused ? t('journal.resume') : t('journal.pause') }}
          </button>
        </div>

        <FlowHistogram
          v-model:segment="segment"
          :stats="stats"
          :period="range ? null : period"
          @range="range = $event"
        />

        <FlowTable
          :flows="flows"
          :selected="selectedId"
          :loading="loading"
          @select="selectedId = $event"
        />
      </section>

      <FlowDetailPanel
        ref="panel"
        class="flex-[1_1_410px]"
        :detail="detail"
        :item="selectedItem"
        :loading="detailLoading"
        @added="onAdded"
      />
    </div>
  </div>
</template>
