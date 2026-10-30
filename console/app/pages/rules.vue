<script setup lang="ts">
import type { Gateway, Install, Revision, Rulebase, VerifyReport, ZoneView } from '~/api/types'

const { t, te } = useI18n()
const api = useApi()
const fmt = useFmt()
const route = useRoute()
const router = useRouter()
const toast = useToast()
const { session, refresh: refreshSession } = usePolicySession()
const { refreshShell, policy } = useShell()

useHead({ title: () => `${t('nav.rules')} — agents-firewall` })

type Phase = 'idle' | 'draft' | 'publish' | 'published' | 'installed'
const phase = ref<Phase>('idle')
const search = ref('')
const zones = ref<ZoneView[]>([])
const rulebase = ref<Rulebase | null>(null)
const report = ref<VerifyReport | null>(null)
const comment = ref('')
const published = ref<Revision | null>(null)
const gateways = ref<Gateway[]>([])
const install = ref<Install | null>(null)
const busy = ref(false)
/** Revision numbers are those the API reports: never predicted by the console. */
const installedRevision = computed(() => policy.data.value?.installed_revision ?? null)

const zoneId = computed(() => (typeof route.query.zone === 'string' ? route.query.zone : zones.value[0]?.id))
const zone = computed(() => zones.value.find(z => z.id === zoneId.value) ?? null)

async function loadRules() {
  if (!zoneId.value) return
  rulebase.value = await api.getRulebase({ zone_id: zoneId.value, q: search.value || undefined })
}

async function loadAll() {
  const [z] = await Promise.all([api.listZones(), refreshSession(), policy.refresh()])
  zones.value = z
  if (phase.value === 'idle' || phase.value === 'draft') phase.value = session.value ? 'draft' : 'idle'
  await loadRules()
}

onMounted(() => void loadAll())
watch(zoneId, () => void loadRules())
let searchTimer: ReturnType<typeof setTimeout> | undefined
watch(search, () => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => void loadRules(), 200)
})

function pickZone(id: string) {
  void router.replace({ query: { ...route.query, zone: id } })
}

async function openSession() {
  await api.openSession(t('rules.defaultSessionName'))
  await refreshSession()
  phase.value = 'draft'
}

async function goPublish() {
  report.value = await api.verify()
  phase.value = 'publish'
}

async function discard() {
  if (!session.value) return
  await api.discardSession(session.value.id)
  await refreshSession()
  phase.value = 'idle'
  await loadAll()
  await refreshShell()
}

async function doPublish() {
  if (!session.value || busy.value) return
  busy.value = true
  try {
    published.value = await api.publishSession(session.value.id, comment.value)
    comment.value = ''
    gateways.value = await api.listGateways()
    await refreshSession()
    phase.value = 'published'
    await Promise.all([loadRules(), refreshShell()])
  }
  catch (e) {
    toast.add({ title: t('rules.publishFailed'), description: e instanceof Error ? e.message : String(e), color: 'error' })
  }
  finally {
    busy.value = false
  }
}

/** Gateways carrying the zones of the published policy: all of them, as listed by the API. */
const targets = computed(() => gateways.value)

async function doInstall() {
  if (!published.value || busy.value || !targets.value.length) return
  busy.value = true
  try {
    install.value = await api.install(published.value.number, targets.value.map(g => g.id))
    phase.value = 'installed'
    await Promise.all([loadRules(), refreshShell()])
  }
  finally {
    busy.value = false
  }
}

const steps = computed(() => {
  const order: Phase[] = ['draft', 'publish', 'published', 'installed']
  const idx = order.indexOf(phase.value)
  const at = idx < 0 ? 0 : [0, 0, 1, 2][idx]!
  const done = idx < 0 ? -1 : [-1, -1, 0, 2][idx]!
  return (['modify', 'publish', 'install'] as const).map((k, i) => ({
    key: k,
    n: i <= done ? '✓' : String(i + 1),
    dotCls: i <= done ? 'bg-ok text-pri-fg' : i === at ? 'bg-pri text-pri-fg' : 'bg-sub text-text3',
    labelCls: i === at ? 'font-[650] text-text' : 'font-medium text-text2',
  }))
})

const bar = computed(() => {
  const s = session.value
  const rev = published.value?.number
  switch (phase.value) {
    case 'draft':
      return { title: t('rules.bar.draft', { name: s?.name ?? '', n: t('session.changes', s?.changes.length ?? 0) }), sub: t('rules.bar.draftSub', { who: s?.owner.name ?? '', when: fmt.rel(s?.opened_at), locks: s?.locked_objects ?? 0 }), bg: 'var(--warn-bg)', fg: 'var(--warn)' }
    case 'publish':
      return { title: t('rules.bar.publish', { name: s?.name ?? '' }), sub: t('rules.bar.publishSub'), bg: 'var(--warn-bg)', fg: 'var(--warn)' }
    case 'published':
      return { title: t('rules.bar.published', { n: rev }), sub: t('rules.bar.publishedSub', { who: published.value?.author.name ?? '', at: fmt.hm(published.value?.published_at), prev: installedRevision.value ?? '—' }), bg: 'var(--pri-bg)', fg: 'var(--pri)' }
    case 'installed':
      return { title: t('rules.bar.installed', { n: policy.data.value?.installed_revision ?? rev, ok: policy.data.value?.gateways_on_revision ?? 0, total: policy.data.value?.gateways_total ?? 0 }), sub: t('rules.bar.installedSub'), bg: 'var(--ok-bg)', fg: 'var(--ok)' }
    default:
      return { title: t('rules.bar.idle'), sub: t('rules.bar.idleSub', { n: installedRevision.value ?? '—' }), bg: 'var(--panel)', fg: 'var(--text3)' }
  }
})

const sign = (op: string) => (op === 'add' ? '+' : op === 'delete' ? '−' : '~')
const signCls = (op: string) => (op === 'add' ? 'text-ok' : op === 'delete' ? 'text-ko' : 'text-text3')
const findingText = (f: VerifyReport['findings'][number]) => (te(`verify.${f.code}`) ? t(`verify.${f.code}`, f.params) : f.message)

function notAvailable() {
  toast.add({ title: t('rules.useCli'), description: 'afw rule add --zone … · afw section add …', icon: 'i-lucide-terminal' })
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.rules')"
      :subtitle="t('rules.subtitle')"
    >
      <template #actions>
        <UInput
          v-model="search"
          icon="i-lucide-search"
          type="search"
          :placeholder="t('rules.search')"
          :aria-label="t('rules.searchLabel')"
          class="min-w-[240px]"
          size="sm"
        />
      </template>
    </ShellPageHeader>

    <section
      :aria-label="t('rules.sessionAria')"
      class="flex flex-wrap items-center gap-[14px] border-b border-line px-4 py-[10px]"
      :style="{ background: bar.bg }"
      data-testid="session-bar"
    >
      <span class="flex min-w-0 items-center gap-[10px]">
        <span
          class="flex size-[30px] items-center justify-center rounded-lg border border-line bg-panel"
          :style="{ color: bar.fg }"
        >
          <UIcon
            name="i-lucide-lock"
            class="size-[15px]"
          />
        </span>
        <span class="flex flex-col leading-[1.3]">
          <strong
            class="text-[13px]"
            data-testid="session-bar-title"
          >{{ bar.title }}</strong>
          <span class="text-xs text-text2">{{ bar.sub }}</span>
        </span>
      </span>
      <ol
        :aria-label="t('rules.steps')"
        class="mx-auto my-0 flex list-none items-center gap-1.5 p-0 text-xs"
      >
        <li
          v-for="(st, i) in steps"
          :key="st.key"
          class="flex items-center gap-1.5"
        >
          <span
            class="flex size-5 items-center justify-center rounded-full text-[11px] font-bold"
            :class="st.dotCls"
          >{{ st.n }}</span>
          <span :class="st.labelCls">{{ t(`steps.${st.key}`) }}</span>
          <span
            v-if="i < 2"
            aria-hidden="true"
            class="px-1 text-text3"
          >→</span>
        </li>
      </ol>
      <span class="flex flex-wrap gap-2">
        <template v-if="phase === 'idle'">
          <UButton
            color="neutral"
            variant="outline"
            @click="openSession"
          >{{ t('rules.openSession') }}</UButton>
        </template>
        <template v-else-if="phase === 'draft' || phase === 'publish'">
          <UButton
            color="neutral"
            variant="outline"
            class="bg-panel"
            data-testid="session-discard"
            @click="discard"
          >{{ t('rules.discard') }}</UButton>
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :disabled="!session?.changes.length"
            data-testid="go-publish"
            @click="goPublish"
          >{{ t('rules.verifyPublish') }}</UButton>
        </template>
        <template v-else-if="phase === 'published'">
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :loading="busy"
            :disabled="!targets.length"
            :title="targets.map(g => g.name).join(', ')"
            data-testid="do-install"
            @click="doInstall"
          >{{ t('rules.installSummary', { n: published?.number, gws: targets.map(g => g.name).join(', ') }, targets.length) }}</UButton>
        </template>
        <template v-else>
          <UButton
            to="/"
            color="neutral"
            variant="outline"
            class="bg-panel font-semibold"
          >{{ t('rules.seeJournal') }}</UButton>
        </template>
      </span>
    </section>

    <section
      v-if="phase === 'publish' && session"
      :aria-label="t('rules.publishAria')"
      class="mx-4 mt-[14px] flex flex-wrap gap-5 rounded-[10px] border border-line2 bg-panel p-4"
      data-testid="publish-panel"
    >
      <div class="flex flex-[1_1_360px] flex-col gap-2">
        <h2 class="m-0 text-sm font-[650]">
          {{ t('rules.diffWith', { n: session.base_revision }) }}
        </h2>
        <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px]">
          <li
            v-for="(c, i) in session.changes"
            :key="i"
            class="flex gap-2"
          >
            <span
              class="w-[14px] font-mono font-bold"
              :class="signCls(c.op)"
            >{{ sign(c.op) }}</span>
            <span><strong>{{ c.summary }}</strong> « {{ c.target }} »<template v-if="c.before || c.after"> · <span class="font-mono text-xs text-text2">{{ c.before ? `${c.before} → ` : '' }}{{ c.after }}</span></template></span>
          </li>
        </ul>
      </div>
      <div class="flex flex-[1_1_300px] flex-col gap-2">
        <h2 class="m-0 text-sm font-[650]">
          {{ t('rules.checks') }}
        </h2>
        <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px]">
          <li
            v-if="!report?.findings.some(f => f.code === 'shadowed_rule')"
            class="flex items-baseline gap-2"
          >
            <span class="font-bold text-ok">OK</span><span>{{ t('rules.noShadow') }}</span>
          </li>
          <li
            v-for="(f, i) in report?.findings ?? []"
            :key="i"
            class="flex items-baseline gap-2"
          >
            <span
              class="font-bold"
              :class="f.severity === 'error' ? 'text-ko' : 'text-warn'"
            >{{ f.severity === 'error' ? '✕' : '1' }}</span><span>{{ findingText(f) }}</span>
          </li>
        </ul>
        <span class="text-[11.5px] text-text3">{{ report?.ok ? t('rules.nonBlocking') : t('rules.blocking') }}</span>
      </div>
      <div class="flex flex-[1_1_260px] flex-col gap-2">
        <label
          for="afw-pubcomment"
          class="text-xs font-semibold"
        >{{ t('rules.revComment') }}</label>
        <UInput
          id="afw-pubcomment"
          v-model="comment"
          :placeholder="t('rules.revCommentPh')"
        />
        <span class="mt-auto flex justify-end gap-2">
          <UButton
            color="neutral"
            variant="outline"
            @click="phase = 'draft'"
          >{{ t('common.cancel') }}</UButton>
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :disabled="!report?.ok"
            :loading="busy"
            data-testid="do-publish"
            @click="doPublish"
          >{{ t('rules.publishRev', { n: session.next_revision }) }}</UButton>
        </span>
      </div>
    </section>

    <section
      v-if="phase === 'installed' && install"
      class="mx-4 mt-[14px] flex flex-wrap items-center gap-x-6 gap-y-[10px] rounded-[10px] border border-line bg-panel px-4 py-3"
      data-testid="install-result"
    >
      <strong class="text-[13px]">{{ t('rules.resultPerGw') }}</strong>
      <span
        v-for="r in install.results"
        :key="r.gateway_id"
        class="flex items-center gap-1.5 text-[12.5px]"
      >
        <span
          class="font-bold"
          :class="r.ok ? 'text-ok' : 'text-ko'"
        >{{ r.ok ? '✓' : '✕' }}</span>
        <span class="font-mono text-xs">{{ r.gateway_name }}</span>
        <span class="text-text3">{{ r.ok ? t('rules.revActive', { n: r.revision, d: fmt.duration(r.duration_ms) }) : r.error }}</span>
      </span>
    </section>

    <div class="flex flex-wrap items-center gap-2 px-4 pt-[14px]">
      <div
        role="tablist"
        :aria-label="t('rules.zone')"
        class="flex flex-wrap gap-1"
      >
        <button
          v-for="z in zones"
          :key="z.id"
          type="button"
          role="tab"
          :aria-selected="z.id === zoneId"
          class="flex h-8 items-center gap-[7px] rounded-[7px] border px-3 text-[12.5px] font-semibold"
          :class="z.id === zoneId ? 'border-text bg-text text-bg' : 'border-line2 bg-panel text-text2'"
          :data-testid="`zone-tab-${z.name}`"
          @click="pickZone(z.id)"
        >
          {{ z.name }}<span class="font-mono text-[11px] font-medium opacity-80">{{ z.rule_count }}</span>
          <span
            v-if="z.mode === 'observe'"
            class="rounded bg-obs-bg px-[5px] text-[10.5px] font-bold text-obs"
          >{{ t('zone.observation') }}</span>
        </button>
      </div>
      <span class="flex-1" />
      <button
        type="button"
        class="flex h-8 items-center gap-1.5 rounded-[7px] border border-line2 bg-panel px-3 font-medium"
        @click="notAvailable"
      >
        <UIcon
          name="i-lucide-plus"
          class="size-[13px]"
        />{{ t('rules.section') }}
      </button>
      <button
        type="button"
        class="flex h-8 items-center gap-1.5 rounded-[7px] border-0 bg-text px-3 font-semibold text-bg"
        @click="notAvailable"
      >
        <UIcon
          name="i-lucide-plus"
          class="size-[13px]"
        />{{ t('rules.rule') }}
      </button>
    </div>

    <div
      v-if="rulebase?.observation"
      class="mx-4 mt-[10px] flex flex-wrap items-center gap-x-4 gap-y-[10px] rounded-lg bg-obs-bg px-[14px] py-[10px] text-[12.5px] text-text"
    >
      <strong class="text-obs">{{ t('zone.observeMode') }}</strong>
      <span>{{ t('rules.observeText', { since: fmt.date(rulebase.observation.since), n: rulebase.observation.destinations, u: rulebase.observation.uncovered }) }}</span>
      <span class="flex-1" />
      <UButton
        color="neutral"
        variant="outline"
        class="bg-panel font-semibold"
        @click="notAvailable"
      >{{ t('rules.proposeFromTraffic') }}</UButton>
      <UButton
        class="bg-obs font-semibold text-white hover:bg-obs/90"
        @click="notAvailable"
      >{{ t('rules.toEnforce') }}</UButton>
    </div>

    <div class="mx-4 mt-[10px] mb-5">
      <RulesRuleTable
        v-if="rulebase && zone"
        :baseline="rulebase.baseline"
        :rules="rulebase.zone"
        :zone-name="zone.name"
        :zone-mode="zone.mode"
      />
      <USkeleton
        v-else
        class="h-64 w-full"
      />
    </div>
  </div>
</template>
