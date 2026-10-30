<script setup lang="ts">
import type { AuditEntry, AuditVerify, Gateway, Revision } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const { session } = usePolicySession()
const { refreshShell, policy } = useShell()

useHead({ title: () => `${t('nav.revisions')} — agents-firewall` })

const revisions = ref<Revision[]>([])
const selected = ref<number | null>(null)
const audit = ref<AuditEntry[]>([])
const chain = ref<AuditVerify | null>(null)
const gateways = ref<Gateway[]>([])
const confirmOpen = ref(false)
const busy = ref(false)

async function load() {
  const [revs, a, v, g] = await Promise.all([api.listRevisions(), api.listAudit({ limit: 9 }), api.verifyAudit(), api.listGateways()])
  revisions.value = revs
  audit.value = a.items
  chain.value = v
  gateways.value = g
  if (selected.value == null) selected.value = revs.find(r => r.installed)?.number ?? revs[0]?.number ?? null
}
onMounted(load)

const cur = computed(() => revisions.value.find(r => r.number === selected.value) ?? null)

const tone = (op: string) => (op === 'add' ? { sign: '+', fg: 'text-ok', bg: 'bg-ok-bg' } : op === 'delete' ? { sign: '−', fg: 'text-ko', bg: 'bg-ko-bg' } : { sign: '~', fg: 'text-warn', bg: 'bg-sub' })

const via = (r: Revision) => (r.interface === 'mcp' ? t('revisions.viaMcp') : t(`audit.iface.${r.interface}`))

async function rollback() {
  if (!cur.value) return
  busy.value = true
  try {
    await api.install(cur.value.number, gateways.value.map(g => g.id))
    toast.add({ title: t('revisions.rolledBack', { n: cur.value.number }), icon: 'i-lucide-undo-2' })
    confirmOpen.value = false
    await Promise.all([load(), refreshShell()])
  }
  finally {
    busy.value = false
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
            v-if="session"
            to="/rules"
            class="flex items-center gap-[10px] border-b border-line bg-warn-bg px-[14px] py-[10px] no-underline"
            style="color: var(--text)"
          >
            <span class="w-[34px] font-mono text-xs font-bold text-warn">—</span>
            <span class="flex flex-col leading-[1.3]">
              <strong class="text-[12.5px]">{{ t('revisions.pending') }}</strong>
              <span class="text-[11.5px] text-text2">{{ session.owner.name }} · {{ t('session.changes', session.changes.length) }} · {{ session.name }}</span>
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
                <strong class="truncate text-[12.5px]">{{ r.title }}</strong>
                <span
                  v-if="r.installed"
                  class="flex-none rounded bg-ok-bg px-[5px] text-[10.5px] font-bold text-ok"
                >{{ t('revisions.installed') }}</span>
              </span>
              <span class="text-[11.5px] text-text2">{{ r.author.name }} · {{ via(r) }}</span>
              <span class="text-[11px] text-text3">{{ fmt.dateTime(r.published_at) }} · {{ t('revisions.changes', r.changes.length) }}</span>
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
                {{ t('revisions.revTitle', { n: cur.number, title: cur.title }) }}
              </h2>
              <span class="text-[12.5px] text-text2">{{ cur.author.name }} · {{ via(cur) }} · {{ fmt.dateTime(cur.published_at) }} · {{ t('revisions.session', { id: cur.session_id }) }}</span>
              <span
                v-if="cur.comment"
                class="text-[12.5px]"
              >« {{ cur.comment }} »</span>
              <span
                v-if="cur.approval"
                class="self-start rounded-[5px] bg-obs-bg px-2 py-0.5 text-[11.5px] font-semibold text-obs"
              >{{ cur.approval }}</span>
            </div>
            <div class="flex flex-wrap gap-2">
              <UButton
                color="neutral"
                variant="outline"
                @click="toast.add({ title: t('rules.useCli'), description: `afw revision diff ${cur.number} --against …`, icon: 'i-lucide-terminal' })"
              >
                {{ t('revisions.compare') }}
              </UButton>
              <UButton
                v-if="!cur.installed"
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
            <div
              v-for="(d, i) in cur.changes"
              :key="i"
              class="grid grid-cols-[26px_150px_minmax(0,1fr)_minmax(0,1fr)] items-start gap-[10px] rounded-[7px] px-[10px] py-2 text-[12.5px]"
              :class="tone(d.op).bg"
            >
              <span
                class="font-mono font-bold"
                :class="tone(d.op).fg"
              >{{ tone(d.op).sign }}</span>
              <span class="flex flex-col leading-[1.3]"><strong class="text-xs">{{ d.summary }}</strong><span class="font-mono text-[11.5px] text-text2">{{ d.target }}</span></span>
              <span
                class="font-mono text-[11.5px] whitespace-pre-line text-text2"
                :class="d.op === 'delete' ? 'line-through' : ''"
              >{{ d.before ?? '—' }}</span>
              <span class="font-mono text-[11.5px] whitespace-pre-line">{{ d.after ?? '—' }}</span>
            </div>
          </div>
          <div class="mt-auto flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line px-4 py-3 text-xs">
            <strong class="text-xs">{{ t('revisions.installation') }}</strong>
            <span
              v-if="!cur.installs.length"
              class="text-text3"
            >{{ t('revisions.notInstalled') }}</span>
            <span
              v-for="g in cur.installs"
              :key="g.gateway_id"
              class="flex items-center gap-1.5"
            >
              <span
                class="font-bold"
                :class="g.ok ? 'text-ok' : 'text-warn'"
              >{{ g.ok ? '✓' : '!' }}</span>
              <span class="font-mono text-[11.5px]">{{ g.gateway_name }}</span>
              <span class="text-text3">{{ g.ok ? (cur.installed ? t('revisions.installedAt', { at: fmt.dateTime(g.at) }) : t('revisions.replacedAt', { at: fmt.dateTime(g.at) })) : g.error }}</span>
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
            />{{ chain.ok ? t('audit.chainOk', { at: fmt.hm(chain.anchor_exported_at) }) : t('audit.chainKo') }}
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
      :description="t('revisions.confirmText', { n: cur?.number, gws: gateways.map(g => g.name).join(', ') })"
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
            @click="rollback"
          >
            {{ t('revisions.rollbackConfirm') }}
          </UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
