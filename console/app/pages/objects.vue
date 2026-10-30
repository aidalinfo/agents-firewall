<script setup lang="ts">
import type { NetObjectView, WhereUsed, ZoneView } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const route = useRoute()

useHead({ title: () => `${t('nav.objects')} — agents-firewall` })

const zones = ref<ZoneView[]>([])
const objects = ref<NetObjectView[]>([])
const type = ref<string>('all')
const search = ref('')
const selected = ref<string | null>(null)
const used = ref<WhereUsed[]>([])

onMounted(async () => {
  const [z, o] = await Promise.all([api.listZones(), api.listObjects()])
  zones.value = z
  objects.value = o
  const want = typeof route.query.object === 'string' ? route.query.object : 'grp-portails-partenaires'
  selected.value = (o.find(x => x.name === want || x.id === want) ?? o[0])?.id ?? null
})

watch(selected, async (id) => {
  used.value = id ? await api.whereUsed(id) : []
})

const TYPES = ['all', 'domain', 'host', 'network', 'group', 'service', 'data_class', 'agent'] as const
const shown = computed(() => {
  const q = search.value.toLowerCase()
  return objects.value
    .filter(o => type.value === 'all' || o.kind === type.value)
    .filter(o => !q || o.name.toLowerCase().includes(q) || o.value.toLowerCase().includes(q))
})
const cur = computed(() => objects.value.find(o => o.id === selected.value) ?? null)

function tag(o: NetObjectView) {
  if (o.in_session) return { label: t('rules.tag.session'), cls: 'bg-pri-bg text-pri' }
  if (o.used_in === 0) return { label: t('objects.unusedTag'), cls: 'bg-warn-bg text-warn' }
  return null
}

function href(u: WhereUsed): string {
  switch (u.kind) {
    case 'rule':
    case 'inspection': {
      const z = zones.value.find(x => x.name === u.zone)
      return z ? `/rules?zone=${z.id}` : '/rules'
    }
    case 'alert': return '/alerts'
    case 'map': return '/internal'
    case 'zone': {
      const z = zones.value.find(x => x.name === u.ref)
      return z ? `/rules?zone=${z.id}` : '/objects'
    }
    case 'gateway': return '/gateways'
    default: return '/'
  }
}

function usedContext(u: WhereUsed): string {
  if (u.kind !== 'rule') return u.note ?? ''
  const where = u.zone ?? t('rules.baselineShort')
  if (u.hits == null) return `${where} · ${t('rules.notInstalled')}`
  return `${where} · ${t('objects.uses', { n: fmt.num(u.hits) }, u.hits)}${u.last_at ? ` · ${fmt.rel(u.last_at)}` : ''}`
}

function history(o: NetObjectView): string {
  if (o.in_session) return t('objects.lockedBySession')
  if (o.kind === 'agent') return t('objects.agentNote')
  if (o.builtin) return t('objects.builtin')
  const c = o.last_change
  if (!c) return ''
  if (o.used_in === 0) return t('objects.noLongerUsed', { n: c.revision })
  return t('objects.changedIn', { n: c.revision, by: c.by }) + (c.at ? ` · ${fmt.date(c.at)}` : '') + (c.note ? ` · ${c.note}` : '')
}

function zoneMode(z: ZoneView) {
  return z.mode === 'observe' ? { label: t('zone.observation'), cls: 'bg-obs-bg text-obs' } : { label: t('zone.enforce'), cls: 'bg-ok-bg text-ok' }
}

function zoneRules(z: ZoneView) {
  const parts = [t('objects.rules', z.rule_count)]
  if (z.rules_in_session) parts.push(t('objects.inSession', z.rules_in_session))
  if (z.expired_rules) parts.push(t('objects.expired', z.expired_rules))
  if (z.observe_since) parts.push(t('objects.since', { d: fmt.date(z.observe_since) }))
  return parts.join(' · ')
}

function delegation(z: ZoneView) {
  if (z.holds_mcp_agent) return { label: t('objects.deleg.self'), cls: 'text-warn' }
  return z.delegated_to_mcp ? { label: t('objects.deleg.yes'), cls: 'text-text' } : { label: t('objects.deleg.no'), cls: 'text-text3' }
}

function notAvailable() {
  toast.add({ title: t('rules.useCli'), description: 'afw object add … · afw zone add …', icon: 'i-lucide-terminal' })
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.objects')"
      :subtitle="t('objects.subtitle')"
    />
    <div class="flex flex-col gap-4 p-4">
      <section
        aria-labelledby="zones-title"
        class="flex flex-col gap-[10px]"
      >
        <div class="flex flex-wrap items-baseline gap-[10px]">
          <h2
            id="zones-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('objects.zones') }}
          </h2>
          <span class="text-xs text-text3">{{ t('objects.zonesNote') }}</span>
          <span class="flex-1" />
          <UButton
            color="neutral"
            variant="outline"
            size="sm"
            class="bg-panel"
            @click="notAvailable"
          >
            {{ t('objects.newZone') }}
          </UButton>
        </div>
        <div class="grid grid-cols-[repeat(auto-fit,minmax(min(250px,100%),1fr))] gap-[10px]">
          <article
            v-for="z in zones"
            :key="z.id"
            class="afw-card flex flex-col gap-2 px-[14px] py-3"
            :data-testid="`zone-card-${z.name}`"
          >
            <div class="flex items-center gap-2">
              <strong class="text-sm">{{ z.name }}</strong>
              <span
                class="rounded px-1.5 py-px text-[11px] font-bold"
                :class="zoneMode(z).cls"
              >{{ zoneMode(z).label }}</span>
            </div>
            <div class="flex flex-wrap gap-1">
              <NuxtLink
                v-for="a in z.agents"
                :key="a.id"
                :to="`/agents/${a.id}`"
                class="rounded-[5px] bg-sub px-[7px] py-px font-mono text-[11.5px] no-underline"
                style="color: var(--text)"
              >{{ a.name }}</NuxtLink>
            </div>
            <dl class="m-0 grid grid-cols-[92px_minmax(0,1fr)] gap-x-2 gap-y-[3px] text-xs">
              <dt class="text-text3">
                {{ t('objects.rulesLabel') }}
              </dt><dd class="m-0">
                <NuxtLink
                  :to="`/rules?zone=${z.id}`"
                  class="no-underline"
                  style="color: var(--text)"
                >{{ zoneRules(z) }}</NuxtLink>
              </dd>
              <dt class="text-text3">
                {{ t('objects.gateway') }}
              </dt><dd class="m-0 font-mono text-[11.5px]">
                {{ z.gateways.join(', ') || '—' }}
              </dd>
              <dt class="text-text3">
                {{ t('objects.delegation') }}
              </dt><dd
                class="m-0"
                :class="delegation(z).cls"
              >
                {{ delegation(z).label }}
              </dd>
            </dl>
          </article>
        </div>
      </section>

      <div class="flex flex-wrap items-start gap-4">
        <section
          aria-labelledby="obj-title"
          class="flex min-w-0 flex-[999_1_560px] flex-col gap-[10px]"
        >
          <div class="flex flex-wrap items-center gap-2">
            <h2
              id="obj-title"
              class="m-0 mr-1.5 text-sm font-[650]"
            >
              {{ t('objects.objects') }}
            </h2>
            <div
              role="group"
              :aria-label="t('objects.typeLabel')"
              class="flex flex-wrap gap-1"
            >
              <button
                v-for="k in TYPES"
                :key="k"
                type="button"
                class="h-7 rounded-full border px-[10px] text-xs font-semibold"
                :class="type === k ? 'border-text bg-text text-bg' : 'border-line2 bg-transparent text-text2'"
                :aria-pressed="type === k"
                @click="type = k"
              >
                {{ t(`objects.type.${k}`) }}
              </button>
            </div>
            <span class="flex-1" />
            <UInput
              v-model="search"
              icon="i-lucide-search"
              type="search"
              size="sm"
              :placeholder="t('objects.search')"
              :aria-label="t('objects.search')"
              class="min-w-[200px]"
            />
            <button
              type="button"
              class="h-[30px] rounded-[7px] border-0 bg-text px-3 text-[12.5px] font-semibold text-bg"
              @click="notAvailable"
            >
              {{ t('objects.newObject') }}
            </button>
          </div>
          <div class="afw-card overflow-x-auto">
            <div class="min-w-[600px]">
              <div class="afw-th grid grid-cols-[112px_minmax(190px,1fr)_minmax(180px,1.2fr)_92px] gap-[10px] border-b border-line px-[14px] py-2">
                <span>{{ t('objects.col.type') }}</span><span>{{ t('objects.col.name') }}</span><span>{{ t('objects.col.value') }}</span><span class="text-right">{{ t('objects.col.used') }}</span>
              </div>
              <button
                v-for="o in shown"
                :key="o.id"
                type="button"
                class="afw-row grid w-full grid-cols-[112px_minmax(190px,1fr)_minmax(180px,1.2fr)_92px] items-center gap-[10px] border-0 border-b border-line bg-transparent px-[14px] py-2 text-left"
                :aria-current="o.id === selected ? 'true' : 'false'"
                @click="selected = o.id"
              >
                <span class="text-[11.5px] text-text2">{{ t(`objects.kind.${o.kind}`) }}</span>
                <span class="flex min-w-0 items-center gap-1.5">
                  <span class="truncate font-mono text-xs font-semibold">{{ o.name }}</span>
                  <span
                    v-if="tag(o)"
                    class="flex-none rounded px-[5px] text-[10.5px] font-bold"
                    :class="tag(o)!.cls"
                  >{{ tag(o)!.label }}</span>
                </span>
                <span class="truncate font-mono text-[11.5px] text-text2">{{ o.value }}</span>
                <span
                  class="text-right text-xs font-semibold"
                  :class="o.used_in ? 'text-text2' : 'text-warn'"
                >{{ o.used_in ? t('objects.places', o.used_in) : t('objects.unused') }}</span>
              </button>
            </div>
          </div>
        </section>

        <aside
          v-if="cur"
          :aria-label="t('objects.detailAria')"
          class="afw-card flex min-w-0 flex-[1_1_380px] flex-col"
          data-testid="object-detail"
        >
          <div class="flex flex-col gap-1.5 border-b border-line px-4 py-[14px]">
            <span class="text-xs text-text3">{{ t(`objects.kind.${cur.kind}`) }}</span>
            <h2 class="m-0 break-all font-mono text-base font-semibold">
              {{ cur.name }}
            </h2>
            <span class="text-[12.5px] text-text2">{{ cur.comment }}</span>
            <div class="flex flex-wrap gap-2 pt-1">
              <UButton
                color="neutral"
                variant="outline"
                size="sm"
                @click="notAvailable"
              >
                {{ t('common.edit') }}
              </UButton>
              <UButton
                color="neutral"
                variant="outline"
                size="sm"
                @click="notAvailable"
              >
                {{ t('common.clone') }}
              </UButton>
              <UButton
                v-if="cur.used_in === 0 && !cur.builtin"
                size="sm"
                class="bg-ko-bg font-semibold text-ko hover:bg-ko-bg"
                @click="notAvailable"
              >
                {{ t('objects.deleteUnused') }}
              </UButton>
            </div>
          </div>
          <div
            v-if="cur.members.length"
            class="flex flex-col gap-1.5 border-b border-line px-4 py-3"
          >
            <strong class="text-xs">{{ cur.kind === 'data_class' ? t('objects.patterns') : t('objects.members') }}</strong>
            <ul class="m-0 flex list-none flex-col gap-[3px] p-0">
              <li
                v-for="m in cur.members"
                :key="m"
                class="font-mono text-xs"
              >
                {{ m }}
              </li>
            </ul>
          </div>
          <div class="flex flex-col gap-2 px-4 pt-3 pb-4">
            <div class="flex items-baseline justify-between gap-2">
              <strong class="text-[13px]">{{ t('objects.whereUsed') }}</strong>
              <span class="text-xs text-text3">{{ used.length ? t('objects.places', used.length) : t('objects.unused') }}</span>
            </div>
            <span
              v-if="!used.length"
              class="rounded-[7px] bg-warn-bg px-[10px] py-2 text-[12.5px] text-warn"
            >{{ t('objects.nowhere') }}</span>
            <ul class="m-0 flex list-none flex-col gap-1.5 p-0">
              <li
                v-for="(u, i) in used"
                :key="i"
              >
                <NuxtLink
                  :to="href(u)"
                  class="flex items-center gap-[10px] rounded-lg border border-line px-[10px] py-2 no-underline"
                  style="color: var(--text)"
                >
                  <span class="w-[76px] flex-none text-[10px] font-bold tracking-[.04em] text-text3 uppercase">{{ u.kind === 'rule' ? t('objects.useKind.rule', { n: u.ref }) : t(`objects.useKind.${u.kind}`) }}</span>
                  <span class="flex min-w-0 flex-col leading-[1.3]">
                    <span class="text-[12.5px] font-semibold">{{ u.name }}</span>
                    <span class="text-[11.5px] text-text3">{{ usedContext(u) }}</span>
                  </span>
                </NuxtLink>
              </li>
            </ul>
            <span class="text-[11.5px] text-text3">{{ history(cur) }}</span>
          </div>
        </aside>
      </div>
    </div>
  </div>
</template>
