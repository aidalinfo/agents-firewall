<script setup lang="ts">
import type { AuditEntry, AuditVerify, Change, Install, Revision, RevisionDiff } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const problem = useProblem()
const dir = useDirectory()
const { session, refresh: refreshSession } = usePolicySession()
const { refreshShell, policy } = useShell()

useHead({ title: () => `${t('nav.revisions')} — agents-firewall` })

const revisions = ref<Revision[]>([])
const selected = ref<number | null>(null)
const diff = ref<RevisionDiff | null>(null)
const installs = ref<Install[]>([])
const audit = ref<AuditEntry[]>([])
const chain = ref<AuditVerify | null>(null)
const confirmOpen = ref(false)
const busy = ref(false)
const installed = computed(() => policy.data.value?.installed_revision ?? null)

async function load() {
  try {
    const [revs, a, v] = await Promise.all([api.listRevisions(), api.listAudit({ limit: 9 }), api.verifyAudit(), dir.ensure(), policy.refresh()])
    revisions.value = revs.items
    // Most recent entries of the chain (the API lists it in ascending order).
    audit.value = a.items.slice(-9).reverse()
    chain.value = v
    if (selected.value == null) selected.value = revs.items.find(r => r.number === installed.value)?.number ?? revs.items[0]?.number ?? null
  }
  catch (e) {
    problem.notify(e)
  }
}
onMounted(load)

watch(selected, async (n) => {
  diff.value = null
  installs.value = []
  if (n == null) return
  const [d, i] = await Promise.all([api.diffRevision(n), api.listInstalls({ revision: n })])
  diff.value = d
  installs.value = i.items
})

const cur = computed(() => revisions.value.find(r => r.number === selected.value) ?? null)

const tone = (k: Change['kind']) => (k === 'added' ? { sign: '+', fg: 'text-ok', bg: 'bg-ok-bg' } : k === 'removed' ? { sign: '−', fg: 'text-ko', bg: 'bg-ko-bg' } : { sign: '~', fg: 'text-warn', bg: 'bg-sub' })
const via = (r: Revision) => (r.interface === 'mcp' ? t('revisions.viaMcp') : t(`audit.iface.${r.interface}`))

/** Fields that differ between before and after (raw values from the API, shown compactly). */
function fields(c: Change): { key: string, before: string, after: string }[] {
  const b = (c.before ?? {}) as Record<string, unknown>
  const a = (c.after ?? {}) as Record<string, unknown>
  const keys = [...new Set([...Object.keys(b), ...Object.keys(a)])].filter(k => k !== 'id' && JSON.stringify(b[k]) !== JSON.stringify(a[k]))
  const show = (v: unknown) => (v === undefined ? '—' : typeof v === 'string' ? v : JSON.stringify(v))
  return keys.map(k => ({ key: k, before: c.before == null ? '—' : show(b[k]), after: c.after == null ? '—' : show(a[k]) }))
}

async function reinstall() {
  if (!cur.value) return
  busy.value = true
  try {
    await api.install(cur.value.number, [])
    toast.add({ title: t('revisions.rolledBack', { n: cur.value.number }), icon: 'i-lucide-undo-2' })
    confirmOpen.value = false
    await Promise.all([load(), refreshShell()])
    installs.value = (await api.listInstalls({ revision: cur.value.number })).items
  }
  catch (e) {
    problem.notify(e)
  }
  finally {
    busy.value = false
  }
}

async function revert() {
  if (!cur.value) return
  try {
    await api.revertToRevision(cur.value.number)
    await refreshSession()
    await navigateTo('/rules')
  }
  catch (e) {
    problem.notify(e)
  }
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.revisions')"
      :subtitle="t('revisions.subtitle')"
    />
    <div class="flex flex-col gap-4 p-4">
      <div class="flex flex-wrap items-start gap-4">
        <section
          aria-labelledby="revs-title"
          class="afw-card flex min-w-0 flex-[1_1_360px] flex-col"
        >
          <div class="flex items-baseline justify-between border-b border-line px-[14px] py-3">
            <h2
              id="revs-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('revisions.title') }}
            </h2>
            <span class="text-xs text-text3">{{ t('revisions.total', { n: policy.data.value?.latest_revision ?? '—' }) }}</span>
          </div>
          <NuxtLink
            v-if="session?.state === 'open'"
            to="/rules"
            class="flex items-center gap-[10px] border-b border-line bg-warn-bg px-[14px] py-[10px] no-underline"
            style="color: var(--text)"
          >
            <span class="w-[34px] font-mono text-xs font-bold text-warn">—</span>
            <span class="flex flex-col leading-[1.3]">
              <strong class="text-[12.5px]">{{ t('revisions.pending') }}</strong>
              <span class="text-[11.5px] text-text2">{{ session.owner.name }} · {{ t('session.changes', session.changes) }} · {{ session.name }}</span>
            </span>
          </NuxtLink>
          <button
            v-for="r in revisions"
            :key="r.number"
            type="button"
            class="afw-row flex w-full items-start gap-[10px] border-0 border-b border-line bg-transparent px-[14px] py-[10px] text-left"
            :aria-current="r.number === selected ? 'true' : 'false'"
            :data-testid="`rev-${r.number}`"
            @click="selected = r.number"
          >
            <span class="w-[34px] flex-none font-mono text-xs font-bold">{{ r.number }}</span>
            <span class="flex min-w-0 flex-1 flex-col gap-0.5 leading-[1.3]">
              <span class="flex items-center gap-1.5">
                <strong class="truncate text-[12.5px]">{{ r.comment || t('revisions.noComment') }}</strong>
                <span
                  v-if="r.number === installed"
                  class="flex-none rounded bg-ok-bg px-[5px] text-[10.5px] font-bold text-ok"
                >{{ t('revisions.installed') }}</span>
              </span>
              <span class="text-[11.5px] text-text2">{{ r.published_by.name }} · {{ via(r) }}</span>
              <span class="text-[11px] text-text3">{{ fmt.dateTime(r.published_at) }} · <span class="font-mono">{{ r.sha256.slice(0, 12) }}</span></span>
            </span>
          </button>
          <span class="px-[14px] py-[10px] text-xs text-text3">{{ t('revisions.older') }}</span>
        </section>

        <section
          v-if="cur"
          aria-labelledby="diff-title"
          class="afw-card flex min-w-0 flex-[999_1_560px] flex-col"
          data-testid="revision-detail"
        >
          <div class="flex flex-wrap items-start gap-x-4 gap-y-[10px] border-b border-line px-4 py-[14px]">
            <div class="flex min-w-0 flex-[1_1_320px] flex-col gap-[3px]">
              <h2
                id="diff-title"
                class="m-0 text-[15px] font-[650]"
              >
                {{ t('revisions.revTitle', { n: cur.number, title: cur.comment || t('revisions.noComment') }) }}
              </h2>
              <span class="text-[12.5px] text-text2">{{ cur.published_by.name }} · {{ via(cur) }} · {{ fmt.dateTime(cur.published_at) }}<template v-if="cur.session_id"> · {{ t('revisions.session', { id: cur.session_id.slice(0, 8) }) }}</template></span>
              <span class="font-mono text-[11px] text-text3">sha256 {{ cur.sha256 }}</span>
            </div>
            <div class="flex flex-wrap gap-2">
              <UButton
                color="neutral"
                variant="outline"
                data-testid="revert"
                @click="revert"
              >
                {{ t('revisions.revert') }}
              </UButton>
              <UButton
                v-if="cur.number !== installed"
                class="bg-text font-semibold text-bg hover:bg-text/90"
                data-testid="rollback"
                @click="confirmOpen = true"
              >
                {{ t('revisions.rollback') }}
              </UButton>
            </div>
          </div>
          <div class="flex flex-col gap-2 px-4 py-3">
            <div class="afw-th grid grid-cols-[26px_150px_minmax(0,1fr)_minmax(0,1fr)] gap-[10px] px-[10px]">
              <span /><span>{{ t('revisions.col.item') }}</span><span>{{ t('revisions.col.before') }}</span><span>{{ t('revisions.col.after') }}</span>
            </div>
            <span
              v-if="diff && !diff.changes.length"
              class="px-[10px] text-[12.5px] text-text3"
            >{{ t('revisions.noChange') }}</span>
            <div
              v-for="(d, i) in diff?.changes ?? []"
              :key="i"
              class="grid grid-cols-[26px_150px_minmax(0,1fr)_minmax(0,1fr)] items-start gap-[10px] rounded-[7px] px-[10px] py-2 text-[12.5px]"
              :class="tone(d.kind).bg"
              :data-testid="`change-${d.resource.kind}`"
            >
              <span
                class="font-mono font-bold"
                :class="tone(d.kind).fg"
              >{{ tone(d.kind).sign }}</span>
              <span class="flex flex-col leading-[1.3]"><strong class="text-xs">{{ t(`resource.${d.resource.kind}`) }}</strong><span class="font-mono text-[11.5px] break-all text-text2">{{ d.resource.name }}</span></span>
              <span
                class="flex min-w-0 flex-col font-mono text-[11.5px] text-text2"
                :class="d.kind === 'removed' ? 'line-through' : ''"
              ><span
                v-for="f in fields(d)"
                :key="f.key"
                class="break-all"
              ><span class="text-text3">{{ f.key }}:</span> {{ f.before }}</span></span>
              <span class="flex min-w-0 flex-col font-mono text-[11.5px]"><span
                v-for="f in fields(d)"
                :key="f.key"
                class="break-all"
              ><span class="text-text3">{{ f.key }}:</span> {{ f.after }}</span></span>
            </div>
          </div>
          <div class="mt-auto flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line px-4 py-3 text-xs">
            <strong class="text-xs">{{ t('revisions.installation') }}</strong>
            <span
              v-if="!installs.length"
              class="text-text3"
            >{{ t('revisions.notInstalled') }}</span>
            <span
              v-for="g in installs"
              :key="g.id"
              class="flex items-center gap-1.5"
            >
              <span
                class="font-bold"
                :class="g.state === 'installed' ? 'text-ok' : g.state === 'failed' ? 'text-ko' : 'text-warn'"
              >{{ g.state === 'installed' ? '✓' : g.state === 'failed' ? '✕' : '…' }}</span>
              <span class="font-mono text-[11.5px]">{{ dir.gatewayName(g.gateway_id) ?? g.gateway_id }}</span>
              <span class="text-text3">{{ g.state === 'installed' ? t('revisions.installedAt', { at: fmt.dateTime(g.acked_at) }) : g.state === 'failed' ? g.error : t('revisions.requestedAt', { at: fmt.dateTime(g.requested_at), who: g.requested_by.name }) }}</span>
            </span>
          </div>
        </section>
      </div>

      <section
        aria-labelledby="audit-title"
        class="afw-card overflow-x-auto"
      >
        <div class="flex flex-wrap items-center gap-[10px] px-[14px] py-3">
          <h2
            id="audit-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('audit.title') }}
          </h2>
          <span class="text-xs text-text3">{{ t('audit.subtitle') }}</span>
          <span class="flex-1" />
          <span
            v-if="chain"
            class="inline-flex items-center gap-1.5 text-xs font-semibold"
            :class="chain.ok ? 'text-ok' : 'text-ko'"
          >
            <UIcon
              :name="chain.ok ? 'i-lucide-shield-check' : 'i-lucide-shield-alert'"
              class="size-[13px]"
            />{{ chain.ok ? t('audit.chainOk', { n: chain.checked, sources: chain.anchor_sources.join(', ') }) : t('audit.chainKo', { seq: chain.broken_at ?? '?' }) }}
          </span>
          <UButton
            to="/audit"
            color="neutral"
            variant="outline"
            size="xs"
          >
            {{ t('audit.full') }}
          </UButton>
        </div>
        <AuditTable :entries="audit" />
      </section>
    </div>

    <UModal
      v-model:open="confirmOpen"
      :title="t('revisions.confirmTitle', { n: cur?.number })"
      :description="t('revisions.confirmText', { n: cur?.number, gws: dir.data.value.gateways.map(g => g.name).join(', ') })"
    >
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="outline"
            @click="confirmOpen = false"
          >
            {{ t('common.cancel') }}
          </UButton>
          <UButton
            color="primary"
            :loading="busy"
            data-testid="rollback-confirm"
            @click="reinstall"
          >
            {{ t('revisions.rollbackConfirm') }}
          </UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
