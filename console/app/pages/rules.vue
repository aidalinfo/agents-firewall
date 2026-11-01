<script setup lang="ts">
import type { Install, Revision, Rule, RuleSection, Rulebase, RuleView, VerifyFinding, VerifyReport } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const route = useRoute()
const router = useRouter()
const problem = useProblem()
const dir = useDirectory()
const { session, isOpen, refresh: refreshSession, ensureOpen, publish, discard: discardSession } = usePolicySession()
const { refreshShell, policy } = useShell()

useHead({ title: () => `${t('nav.rules')} — agents-firewall` })

type Phase = 'idle' | 'draft' | 'publish' | 'approval' | 'published' | 'installed'
const search = ref('')
const rulebase = ref<Rulebase | null>(null)
const report = ref<VerifyReport | null>(null)
const comment = ref('')
const verifying = ref(false)
const published = ref<Revision | null>(null)
const installs = ref<Install[]>([])
const installedRev = ref<number | null>(null)
const busy = ref(false)
/** Revision numbers are those the API reports: never predicted by the console. */
const installedRevision = computed(() => policy.data.value?.installed_revision ?? null)
/** Published by the caller and not installed yet (survives a reload: `Session.pending_install`). */
const pendingInstall = computed(() => (installedRev.value === null ? session.value?.pending_install ?? null : null))

const phase = computed<Phase>(() => {
  if (installedRev.value !== null) return 'installed'
  if (isOpen.value) {
    if (session.value?.approval_id) return 'approval'
    return verifying.value ? 'publish' : 'draft'
  }
  if (pendingInstall.value) return 'published'
  return 'idle'
})

const zones = computed(() => rulebase.value?.zones ?? [])
const zoneId = computed(() => (typeof route.query.zone === 'string' && zones.value.some(z => z.zone.id === route.query.zone) ? route.query.zone : zones.value[0]?.zone.id))
const layer = computed(() => zones.value.find(z => z.zone.id === zoneId.value) ?? null)
const zoneRules = computed(() => layer.value?.sections.flatMap(s => s.rules) ?? [])
const allRules = computed(() => [...(rulebase.value?.baseline.sections ?? []), ...zones.value.flatMap(z => z.sections)].flatMap(s => s.rules))

/** Filters the rule views by the search box (name, comment, section, number). */
function filterSections(sections: RuleSection[]): RuleSection[] {
  const q = search.value.trim().toLowerCase()
  if (!q) return sections
  return sections
    .map(s => ({ ...s, rules: s.rules.filter(r => `${r.number} ${r.name} ${r.comment} ${r.section ?? ''}`.toLowerCase().includes(q)) }))
    .filter(s => s.rules.length)
}

async function loadRules() {
  rulebase.value = await api.getRulebase()
}

async function loadAll() {
  await Promise.all([refreshSession(), policy.refresh(), dir.ensure()])
  await loadRules()
}

onMounted(() => void loadAll())
watch(() => session.value?.id, () => void loadRules())

function pickZone(id: string) {
  void router.replace({ query: { ...route.query, zone: id } })
}

async function guarded<T>(fn: () => Promise<T>): Promise<T | undefined> {
  try {
    return await fn()
  }
  catch (e) {
    problem.notify(e)
    await loadRules()
    return undefined
  }
}

async function openSession() {
  await guarded(() => ensureOpen(t('rules.defaultSessionName')))
  await loadRules()
}

async function goPublish() {
  report.value = (await guarded(() => api.verify())) ?? null
  verifying.value = true
}

async function discard() {
  await guarded(() => discardSession())
  verifying.value = false
  await Promise.all([loadRules(), dir.refresh(), refreshShell()])
}

async function doPublish() {
  if (!session.value || busy.value) return
  busy.value = true
  try {
    const out = await publish(comment.value)
    comment.value = ''
    verifying.value = false
    if (out.status === 'published') published.value = out.revision
  }
  catch (e) {
    problem.notify(e, t('rules.publishFailed'))
  }
  finally {
    busy.value = false
  }
  await Promise.all([loadRules(), refreshShell()])
}

let pollTimer: ReturnType<typeof setTimeout> | null = null
async function pollInstalls(n: number, left = 20) {
  const page = await api.listInstalls({ revision: n })
  installs.value = page.items
  await refreshShell()
  if (left > 0 && installs.value.some(i => i.state === 'pending')) pollTimer = setTimeout(() => void pollInstalls(n, left - 1), 1500)
}
onBeforeUnmount(() => {
  if (pollTimer) clearTimeout(pollTimer)
})

async function doInstall() {
  const n = pendingInstall.value
  if (!n || busy.value) return
  busy.value = true
  try {
    const res = await api.install(n, [])
    installs.value = res.installs
    installedRev.value = n
    await Promise.all([refreshSession(), loadRules()])
    void pollInstalls(n)
  }
  catch (e) {
    problem.notify(e, t('rules.installFailed'))
  }
  finally {
    busy.value = false
  }
}

const steps = computed(() => {
  const order: Phase[] = ['draft', 'publish', 'approval', 'published', 'installed']
  const idx = order.indexOf(phase.value)
  const at = idx < 0 ? 0 : [0, 1, 1, 2, 2][idx]!
  const done = idx < 0 ? -1 : [-1, 0, 0, 1, 2][idx]!
  return (['modify', 'publish', 'install'] as const).map((k, i) => ({
    key: k,
    n: i <= done ? '✓' : String(i + 1),
    dotCls: i <= done ? 'bg-ok text-pri-fg' : i === at ? 'bg-pri text-pri-fg' : 'bg-sub text-text3',
    labelCls: i === at ? 'font-[650] text-text' : 'font-medium text-text2',
  }))
})

const bar = computed(() => {
  const s = session.value
  switch (phase.value) {
    case 'draft':
      return { title: t('rules.bar.draft', { name: s?.name ?? '', n: t('session.changes', s?.changes ?? 0) }), sub: t('rules.bar.draftSub', { who: s?.owner.name ?? '', when: fmt.rel(s?.opened_at), locks: s?.locks.length ?? 0 }), bg: 'var(--warn-bg)', fg: 'var(--warn)' }
    case 'publish':
      return { title: t('rules.bar.publish', { name: s?.name ?? '' }), sub: t('rules.bar.publishSub'), bg: 'var(--warn-bg)', fg: 'var(--warn)' }
    case 'approval':
      return { title: t('rules.bar.approval'), sub: t('rules.bar.approvalSub'), bg: 'var(--warn-bg)', fg: 'var(--warn)' }
    case 'published':
      return { title: t('rules.bar.published', { n: pendingInstall.value }), sub: t('rules.bar.publishedSub', { who: published.value?.published_by.name ?? s?.owner.name ?? '', at: fmt.hm(published.value?.published_at ?? s?.closed_at), prev: installedRevision.value ?? '—' }), bg: 'var(--pri-bg)', fg: 'var(--pri)' }
    case 'installed':
      return { title: t('rules.bar.installed', { n: installedRev.value, ok: installs.value.filter(i => i.state === 'installed').length, total: installs.value.length }), sub: t('rules.bar.installedSub'), bg: 'var(--ok-bg)', fg: 'var(--ok)' }
    default:
      return { title: t('rules.bar.idle'), sub: t('rules.bar.idleSub', { n: installedRevision.value ?? '—' }), bg: 'var(--panel)', fg: 'var(--text3)' }
  }
})

const ruleName = (id: string) => {
  const r = allRules.value.find(x => x.id === id)
  return r ? `${r.number} · ${r.name}` : id
}
function findingText(f: VerifyFinding): string {
  switch (f.type) {
    case 'shadowed': return t('verify.shadowed', { rule: ruleName(f.rule), by: ruleName(f.by) })
    case 'expired': return t('verify.expired', { rule: ruleName(f.rule) })
    case 'unused_object': return t('verify.unused_object', { name: dir.objectName(f.id) ?? f.id })
  }
}

// --- forms (EF-44) ---
const ruleFormOpen = ref(false)
const editing = ref<Rule | null>(null)
const sectionFormOpen = ref(false)
const sectionRules = ref<RuleView[]>([])
const sectionName = ref<string | null>(null)
const zoneFormOpen = ref(false)
const zoneEditing = ref(false)

function newRule() {
  editing.value = null
  ruleFormOpen.value = true
}
function editRule(r: RuleView) {
  const { number: _n, hits: _h, last_hit_at: _l, expired: _e, locked_by: _b, pending_change: _p, ...rule } = r
  editing.value = rule
  ruleFormOpen.value = true
}
function newSection() {
  sectionName.value = null
  sectionRules.value = zoneRules.value
  sectionFormOpen.value = true
}
function editSection(s: RuleSection) {
  const isBaseline = s.rules[0]?.layer.type === 'baseline'
  sectionRules.value = isBaseline ? (rulebase.value?.baseline.sections.flatMap(x => x.rules) ?? []) : zoneRules.value
  sectionName.value = s.name ?? null
  sectionFormOpen.value = true
}
async function removeRule(r: RuleView) {
  await guarded(async () => {
    const s = await ensureOpen(t('rules.defaultSessionName'))
    await api.rules.remove(s.id, r.id)
    await refreshSession()
  })
  await loadRules()
}
async function moveRule(r: RuleView, position: number) {
  await guarded(async () => {
    const s = await ensureOpen(t('rules.defaultSessionName'))
    await api.moveRule(s.id, r.id, { position })
    await refreshSession()
  })
  await loadRules()
}
function newZone() {
  zoneEditing.value = false
  zoneFormOpen.value = true
}
function editZone() {
  zoneEditing.value = true
  zoneFormOpen.value = true
}
async function toEnforce() {
  const z = layer.value?.zone
  if (!z) return
  await guarded(async () => {
    const s = await ensureOpen(t('rules.defaultSessionName'))
    await api.zones.update(s.id, { ...z, mode: 'enforce' })
    await refreshSession()
  })
  await loadRules()
}
async function onSaved(z?: { id: string }) {
  await loadRules()
  if (z && zones.value.some(x => x.zone.id === z.id)) pickZone(z.id)
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
          data-testid="rules-search"
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
        <template v-if="phase === 'idle' || phase === 'installed'">
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
            :disabled="!session?.changes"
            data-testid="go-publish"
            @click="goPublish"
          >{{ t('rules.verifyPublish') }}</UButton>
        </template>
        <template v-else-if="phase === 'approval'">
          <UButton
            color="neutral"
            variant="outline"
            class="bg-panel"
            data-testid="session-discard"
            @click="discard"
          >{{ t('rules.discard') }}</UButton>
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :loading="busy"
            data-testid="do-publish-again"
            @click="doPublish"
          >{{ t('rules.publishAgain') }}</UButton>
        </template>
        <template v-else-if="phase === 'published'">
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :loading="busy"
            :title="dir.data.value.gateways.map(g => g.name).join(', ')"
            data-testid="do-install"
            @click="doInstall"
          >{{ t('rules.installAll', { n: pendingInstall, count: dir.data.value.gateways.length }) }}</UButton>
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
          {{ t('rules.diffWith', { n: session.base_revision ?? '—' }) }}
        </h2>
        <span class="text-[12.5px] text-text2">{{ t('session.changes', session.changes) }}</span>
        <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px]">
          <li
            v-for="l in session.locks"
            :key="`${l.kind}:${l.id}`"
            class="flex gap-2"
          >
            <span class="w-[14px] font-mono font-bold text-warn">~</span>
            <span><strong>{{ t(`resource.${l.kind}`) }}</strong> « {{ l.name }} »</span>
          </li>
        </ul>
      </div>
      <div class="flex flex-[1_1_300px] flex-col gap-2">
        <h2 class="m-0 text-sm font-[650]">
          {{ t('rules.checks') }}
        </h2>
        <ul class="m-0 flex list-none flex-col gap-1.5 p-0 text-[12.5px]">
          <li
            v-if="!report?.findings.some(f => f.type === 'shadowed')"
            class="flex items-baseline gap-2"
          >
            <span class="font-bold text-ok">OK</span><span>{{ t('rules.noShadow') }}</span>
          </li>
          <li
            v-for="(f, i) in report?.findings ?? []"
            :key="i"
            class="flex items-baseline gap-2"
          >
            <span class="font-bold text-warn">!</span><span>{{ findingText(f) }}</span>
          </li>
        </ul>
        <span class="text-[11.5px] text-text3">{{ t('rules.nonBlocking') }}</span>
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
            @click="verifying = false"
          >{{ t('common.cancel') }}</UButton>
          <UButton
            class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
            :loading="busy"
            data-testid="do-publish"
            @click="doPublish"
          >{{ t('rules.publishRev', { n: session.next_revision }) }}</UButton>
        </span>
      </div>
    </section>

    <section
      v-if="phase === 'installed'"
      class="mx-4 mt-[14px] flex flex-wrap items-center gap-x-6 gap-y-[10px] rounded-[10px] border border-line bg-panel px-4 py-3"
      data-testid="install-result"
    >
      <strong class="text-[13px]">{{ t('rules.resultPerGw') }}</strong>
      <span
        v-for="r in installs"
        :key="r.id"
        class="flex items-center gap-1.5 text-[12.5px]"
        :data-testid="`install-${r.state}`"
      >
        <span
          class="font-bold"
          :class="r.state === 'installed' ? 'text-ok' : r.state === 'failed' ? 'text-ko' : 'text-warn'"
        >{{ r.state === 'installed' ? '✓' : r.state === 'failed' ? '✕' : '…' }}</span>
        <span class="font-mono text-xs">{{ dir.gatewayName(r.gateway_id) ?? r.gateway_id }}</span>
        <span class="text-text3">{{ r.state === 'installed' ? t('rules.revActive', { n: r.revision, at: fmt.hm(r.acked_at) }) : r.state === 'failed' ? r.error : t('rules.waitingAck', { n: r.revision }) }}</span>
      </span>
      <span
        v-if="!installs.length"
        class="text-[12.5px] text-text3"
      >{{ t('rules.noGateway') }}</span>
    </section>

    <div class="flex flex-wrap items-center gap-2 px-4 pt-[14px]">
      <div
        role="tablist"
        :aria-label="t('rules.zone')"
        class="flex flex-wrap gap-1"
      >
        <button
          v-for="z in zones"
          :key="z.zone.id"
          type="button"
          role="tab"
          :aria-selected="z.zone.id === zoneId"
          class="flex h-8 items-center gap-[7px] rounded-[7px] border px-3 text-[12.5px] font-semibold"
          :class="z.zone.id === zoneId ? 'border-text bg-text text-bg' : 'border-line2 bg-panel text-text2'"
          :data-testid="`zone-tab-${z.zone.name}`"
          @click="pickZone(z.zone.id)"
        >
          {{ z.zone.name }}<span class="font-mono text-[11px] font-medium opacity-80">{{ z.sections.reduce((n, s) => n + s.rules.length, 0) }}</span>
          <span
            v-if="z.mode === 'observe'"
            class="rounded bg-obs-bg px-[5px] text-[10.5px] font-bold text-obs"
          >{{ t('zone.observation') }}</span>
        </button>
      </div>
      <button
        type="button"
        class="afw-ghost flex h-8 items-center gap-1.5 rounded-[7px] px-2 text-[12px] font-medium text-text3"
        data-testid="zone-new"
        @click="newZone"
      >
        <UIcon
          name="i-lucide-plus"
          class="size-[12px]"
        />{{ t('zone.new') }}
      </button>
      <span class="flex-1" />
      <button
        v-if="layer"
        type="button"
        class="flex h-8 items-center gap-1.5 rounded-[7px] border border-line2 bg-panel px-3 font-medium"
        data-testid="zone-edit"
        @click="editZone"
      >
        <UIcon
          name="i-lucide-pencil"
          class="size-[13px]"
        />{{ t('zone.edit') }}
      </button>
      <button
        type="button"
        class="flex h-8 items-center gap-1.5 rounded-[7px] border border-line2 bg-panel px-3 font-medium"
        data-testid="section-new"
        @click="newSection"
      >
        <UIcon
          name="i-lucide-plus"
          class="size-[13px]"
        />{{ t('rules.section') }}
      </button>
      <button
        type="button"
        class="flex h-8 items-center gap-1.5 rounded-[7px] border-0 bg-text px-3 font-semibold text-bg"
        data-testid="rule-new"
        @click="newRule"
      >
        <UIcon
          name="i-lucide-plus"
          class="size-[13px]"
        />{{ t('rules.rule') }}
      </button>
    </div>

    <div
      v-if="layer?.mode === 'observe'"
      class="mx-4 mt-[10px] flex flex-wrap items-center gap-x-4 gap-y-[10px] rounded-lg bg-obs-bg px-[14px] py-[10px] text-[12.5px] text-text"
    >
      <strong class="text-obs">{{ t('zone.observeMode') }}</strong>
      <span>{{ t('rules.observeText') }}</span>
      <span class="flex-1" />
      <UButton
        :to="{ path: '/', query: { q: `zone:${layer.zone.name}` } }"
        color="neutral"
        variant="outline"
        class="bg-panel font-semibold"
      >{{ t('rules.observedFlows') }}</UButton>
      <UButton
        class="bg-obs font-semibold text-white hover:bg-obs/90"
        data-testid="zone-enforce"
        @click="toEnforce"
      >{{ t('rules.toEnforce') }}</UButton>
    </div>

    <div class="mx-4 mt-[10px] mb-5">
      <RulesRuleTable
        v-if="rulebase && layer"
        :baseline="filterSections(rulebase.baseline.sections)"
        :sections="filterSections(layer.sections)"
        :zone-name="layer.zone.name"
        :zone-mode="layer.mode"
        :cleanup-number="layer.cleanup_number"
        editable
        @edit="editRule"
        @remove="removeRule"
        @move="moveRule"
        @section="editSection"
      />
      <div
        v-else-if="rulebase && !zones.length"
        class="afw-card p-6 text-center text-text3"
      >
        {{ t('rules.noZone') }}
      </div>
      <USkeleton
        v-else
        class="h-64 w-full"
      />
    </div>
    <FormsRuleForm
      v-model:open="ruleFormOpen"
      :rule="editing"
      :layer-zone="zoneId"
      @saved="onSaved()"
    />
    <FormsSectionForm
      v-model:open="sectionFormOpen"
      :rules="sectionRules"
      :current="sectionName"
      @saved="onSaved()"
    />
    <FormsZoneForm
      v-model:open="zoneFormOpen"
      :zone="zoneEditing ? layer?.zone ?? null : null"
      @saved="onSaved"
    />
  </div>
</template>
