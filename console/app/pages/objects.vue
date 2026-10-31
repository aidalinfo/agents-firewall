<script setup lang="ts">
import type { Agent, DataClass, NetObject, ResourceKind, ResourceRef, Rule, Service, Zone } from '~/api/types'
import { formatDetectors, formatPorts } from '~/utils/forms'

const { t } = useI18n()
const api = useApi()
const route = useRoute()
const problem = useProblem()
const dir = useDirectory()
const { session, ensureOpen, refresh: refreshSession } = usePolicySession()

useHead({ title: () => `${t('nav.objects')} — agents-firewall` })

type RowKind = NetObject['spec']['type'] | 'service' | 'data_class' | 'agent'
interface Row {
  id: string
  kind: RowKind
  resource: ResourceKind
  name: string
  value: string
  comment: string
  members: string[]
  builtin: boolean
  ref: NetObject | Service | DataClass | Agent
}

const rules = ref<Rule[]>([])
const type = ref<string>('all')
const search = ref('')
const selected = ref<string | null>(null)
const used = ref<ResourceRef[]>([])

async function load() {
  await dir.refresh()
  rules.value = await api.rules.list()
}

onMounted(async () => {
  await load()
  const want = typeof route.query.object === 'string' ? route.query.object : null
  selected.value = (rows.value.find(x => x.name === want || x.id === want) ?? rows.value[0])?.id ?? null
})
watch(() => session.value?.id, () => void load())

function spec(o: NetObject): string {
  const s = o.spec
  switch (s.type) {
    case 'domain': return s.pattern
    case 'host': return s.ip
    case 'network': return s.cidr
    case 'range': return `${s.start} – ${s.end}`
    case 'group': return t('objects.membersCount', s.members.length)
    default: return t('rules.anyDest')
  }
}

const rows = computed<Row[]>(() => {
  const d = dir.data.value
  return [
    ...d.objects.map(o => ({ id: o.id, kind: o.spec.type, resource: 'object' as const, name: o.name, value: spec(o), comment: o.comment, members: o.spec.type === 'group' ? o.spec.members.map(m => dir.objectName(m) ?? m) : [], builtin: false, ref: o })),
    ...d.services.map(s => ({ id: s.id, kind: 'service' as const, resource: 'service' as const, name: s.name, value: `${s.protocol.toUpperCase()} ${formatPorts(s.ports) || t('services.anyPort')}${s.app ? ` · ${s.app.proto}` : ''}`, comment: s.comment, members: s.app ? [...s.app.methods, ...s.app.path_prefixes] : [], builtin: false, ref: s })),
    ...d.dataClasses.map(c => ({ id: c.id, kind: 'data_class' as const, resource: 'data_class' as const, name: c.name, value: t(`dataClasses.category.${c.category}`), comment: c.comment, members: formatDetectors(c.detectors).split('\n').filter(Boolean), builtin: false, ref: c })),
    ...d.agents.map(a => ({ id: a.id, kind: 'agent' as const, resource: 'agent' as const, name: a.name, value: `${a.addresses.join(', ')} · @${dir.zoneName(a.zone_id) ?? ''}`, comment: '', members: [], builtin: false, ref: a })),
  ]
})

/** Rules of the policy referencing each resource (from the rule list of the API). */
const ruleRefs = computed(() => {
  const m = new Map<string, number>()
  for (const r of rules.value) for (const id of new Set([...r.destinations, ...r.services, ...r.data_classes, ...r.sources])) m.set(id, (m.get(id) ?? 0) + 1)
  return m
})
const groupRefs = computed(() => {
  const m = new Map<string, number>()
  for (const o of dir.data.value.objects) if (o.spec.type === 'group') for (const id of o.spec.members) m.set(id, (m.get(id) ?? 0) + 1)
  return m
})
const usedIn = (r: Row) => (ruleRefs.value.get(r.id) ?? 0) + (groupRefs.value.get(r.id) ?? 0)

watch(selected, async (id) => {
  const r = rows.value.find(x => x.id === id)
  used.value = []
  if (!r || r.kind === 'agent') return
  try {
    used.value = (await api.whereUsed(r.id)).references
  }
  catch (e) {
    problem.notify(e)
  }
})

const TYPES = ['all', 'domain', 'host', 'network', 'range', 'group', 'service', 'data_class', 'agent'] as const
const shown = computed(() => {
  const q = search.value.toLowerCase()
  return rows.value
    .filter(o => type.value === 'all' || o.kind === type.value)
    .filter(o => !q || o.name.toLowerCase().includes(q) || o.value.toLowerCase().includes(q))
})
const cur = computed(() => rows.value.find(o => o.id === selected.value) ?? null)
const inSession = (r: Row) => !!session.value?.locks.some(l => l.id === r.id)

function tag(o: Row) {
  if (inSession(o)) return { label: t('rules.tag.session'), cls: 'bg-pri-bg text-pri' }
  if (o.kind !== 'agent' && usedIn(o) === 0) return { label: t('objects.unusedTag'), cls: 'bg-warn-bg text-warn' }
  return null
}

function href(u: ResourceRef): string {
  switch (u.kind) {
    case 'rule': {
      const r = rules.value.find(x => x.id === u.id)
      return r?.layer.type === 'zone' ? `/rules?zone=${r.layer.zone_id}` : '/rules'
    }
    case 'inspection_rule': return '/inspection'
    case 'zone': return `/rules?zone=${u.id}`
    case 'agent': return `/agents/${u.id}`
    default: return `/objects?object=${u.id}`
  }
}

// --- zones ---
function zoneMode(z: Zone) {
  return z.mode === 'observe' ? { label: t('zone.observation'), cls: 'bg-obs-bg text-obs' } : { label: t('zone.enforce'), cls: 'bg-ok-bg text-ok' }
}
function zoneRules(z: Zone) {
  const n = rules.value.filter(r => r.layer.type === 'zone' && r.layer.zone_id === z.id).length
  return t('objects.rules', n)
}
const zoneGateways = (z: Zone) => [...new Set(dir.zoneAgents(z.id).map(a => dir.gatewayName(a.gateway_id)).filter(Boolean))].join(', ')
function delegation(z: Zone) {
  // The approved MCP agent can never change the rules that apply to itself (EF-51).
  if (z.delegated_to_mcp && dir.zoneAgents(z.id).some(a => a.mcp_admin)) return { label: t('objects.deleg.self'), cls: 'text-warn' }
  return z.delegated_to_mcp ? { label: t('objects.deleg.yes'), cls: 'text-text' } : { label: t('objects.deleg.no'), cls: 'text-text3' }
}

// --- forms (EF-44) ---
const forms = reactive({ object: false, service: false, dataClass: false, zone: false, agent: false })
const editObject = ref<NetObject | null>(null)
const editService = ref<Service | null>(null)
const editDataClass = ref<DataClass | null>(null)
const editZone = ref<Zone | null>(null)
const moveAgent = ref<Agent | null>(null)

function create(kind: 'object' | 'service' | 'dataClass') {
  editObject.value = null
  editService.value = null
  editDataClass.value = null
  forms[kind] = true
}
function edit(r: Row) {
  cloneSource.value = null
  if (r.resource === 'object') {
    editObject.value = r.ref as NetObject
    forms.object = true
  }
  else if (r.resource === 'service') {
    editService.value = r.ref as Service
    forms.service = true
  }
  else if (r.resource === 'data_class') {
    editDataClass.value = r.ref as DataClass
    forms.dataClass = true
  }
  else if (r.resource === 'agent') {
    moveAgent.value = r.ref as Agent
    forms.agent = true
  }
}
const cloneSource = ref<NetObject | null>(null)
function cloneObject(r: Row) {
  cloneSource.value = { ...structuredClone(toRaw(r.ref as NetObject)), name: `${r.name}-copie` }
  editObject.value = null
  forms.object = true
}

async function remove(r: Row) {
  try {
    const s = await ensureOpen(t('rules.defaultSessionName'))
    if (r.resource === 'object') await api.objects.remove(s.id, r.id)
    else if (r.resource === 'service') await api.services.remove(s.id, r.id)
    else if (r.resource === 'data_class') await api.dataClasses.remove(s.id, r.id)
    else await api.agents.remove(s.id, r.id)
    await refreshSession()
    selected.value = null
    await load()
  }
  catch (e) {
    problem.notify(e)
  }
}

function newZone() {
  editZone.value = null
  forms.zone = true
}
function openZone(z: Zone) {
  editZone.value = z
  forms.zone = true
}
async function onSaved(v?: { id: string }) {
  cloneSource.value = null
  await load()
  if (v) selected.value = v.id
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
            data-testid="zone-create"
            @click="newZone"
          >
            {{ t('objects.newZone') }}
          </UButton>
        </div>
        <div class="grid grid-cols-[repeat(auto-fit,minmax(min(250px,100%),1fr))] gap-[10px]">
          <article
            v-for="z in dir.data.value.zones"
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
              <span class="flex-1" />
              <button
                type="button"
                class="afw-ghost flex size-6 items-center justify-center rounded"
                :aria-label="t('zone.edit')"
                :data-testid="`zone-edit-${z.name}`"
                @click="openZone(z)"
              >
                <UIcon
                  name="i-lucide-pencil"
                  class="size-3"
                />
              </button>
            </div>
            <span
              v-if="z.comment"
              class="text-[11.5px] text-text3"
            >{{ z.comment }}</span>
            <div class="flex flex-wrap gap-1">
              <NuxtLink
                v-for="a in dir.zoneAgents(z.id)"
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
                {{ zoneGateways(z) || '—' }}
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
            <UDropdownMenu
              :items="[[
                { label: t('objects.newObject'), icon: 'i-lucide-plus', onSelect: () => create('object') },
                { label: t('services.form.create'), icon: 'i-lucide-plus', onSelect: () => create('service') },
                { label: t('dataClasses.form.create'), icon: 'i-lucide-plus', onSelect: () => create('dataClass') },
              ]]"
            >
              <button
                type="button"
                class="h-[30px] rounded-[7px] border-0 bg-text px-3 text-[12.5px] font-semibold text-bg"
                data-testid="object-create"
              >
                {{ t('objects.new') }}
              </button>
            </UDropdownMenu>
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
                  :class="o.kind === 'agent' || usedIn(o) ? 'text-text2' : 'text-warn'"
                >{{ o.kind === 'agent' ? '—' : usedIn(o) ? t('objects.places', usedIn(o)) : t('objects.unused') }}</span>
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
                data-testid="object-edit"
                @click="edit(cur)"
              >
                {{ cur.kind === 'agent' ? t('agents.move.button') : t('common.edit') }}
              </UButton>
              <UButton
                v-if="cur.resource === 'object'"
                color="neutral"
                variant="outline"
                size="sm"
                @click="cloneObject(cur)"
              >
                {{ t('common.clone') }}
              </UButton>
              <UButton
                v-if="cur.kind === 'agent'"
                :to="`/agents/${cur.id}`"
                color="neutral"
                variant="outline"
                size="sm"
              >
                {{ t('agents.open') }}
              </UButton>
              <UButton
                v-if="cur.kind !== 'agent'"
                size="sm"
                class="bg-ko-bg font-semibold text-ko hover:bg-ko-bg"
                data-testid="object-delete"
                @click="remove(cur)"
              >
                {{ usedIn(cur) === 0 ? t('objects.deleteUnused') : t('common.delete') }}
              </UButton>
            </div>
          </div>
          <div
            v-if="cur.members.length"
            class="flex flex-col gap-1.5 border-b border-line px-4 py-3"
          >
            <strong class="text-xs">{{ cur.kind === 'data_class' ? t('objects.patterns') : cur.kind === 'service' ? t('services.appMatch') : t('objects.members') }}</strong>
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
              v-if="!used.length && cur.kind !== 'agent'"
              class="rounded-[7px] bg-warn-bg px-[10px] py-2 text-[12.5px] text-warn"
            >{{ t('objects.nowhere') }}</span>
            <ul class="m-0 flex list-none flex-col gap-1.5 p-0">
              <li
                v-for="u in used"
                :key="`${u.kind}:${u.id}`"
              >
                <NuxtLink
                  :to="href(u)"
                  class="flex items-center gap-[10px] rounded-lg border border-line px-[10px] py-2 no-underline"
                  style="color: var(--text)"
                >
                  <span class="w-[86px] flex-none text-[10px] font-bold tracking-[.04em] text-text3 uppercase">{{ t(`resource.${u.kind}`) }}</span>
                  <span class="text-[12.5px] font-semibold">{{ u.name }}</span>
                </NuxtLink>
              </li>
            </ul>
            <span
              v-if="inSession(cur)"
              class="text-[11.5px] text-text3"
            >{{ t('objects.lockedBySession') }}</span>
          </div>
        </aside>
      </div>
    </div>
    <FormsObjectForm
      v-model:open="forms.object"
      :object="editObject ?? cloneSource"
      :clone="!!cloneSource && !editObject"
      @saved="onSaved"
    />
    <FormsServiceForm
      v-model:open="forms.service"
      :service="editService"
      @saved="onSaved"
    />
    <FormsDataClassForm
      v-model:open="forms.dataClass"
      :data-class="editDataClass"
      @saved="onSaved"
    />
    <FormsZoneForm
      v-model:open="forms.zone"
      :zone="editZone"
      @saved="onSaved()"
    />
    <FormsAgentZoneForm
      v-model:open="forms.agent"
      :agent="moveAgent"
      @saved="onSaved"
    />
  </div>
</template>
