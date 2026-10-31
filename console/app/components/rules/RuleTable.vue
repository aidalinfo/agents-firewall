<script setup lang="ts">
import type { RuleSection, RuleView, ZoneMode } from '~/api/types'

const props = defineProps<{
  baseline: RuleSection[]
  sections: RuleSection[]
  zoneName: string
  zoneMode: ZoneMode
  /** Number of the zone's implicit cleanup rule (display only, from the API). */
  cleanupNumber: number
  editable?: boolean
}>()
const emit = defineEmits<{
  edit: [RuleView]
  remove: [RuleView]
  move: [RuleView, number]
  section: [RuleSection]
}>()

const { t } = useI18n()
const fmt = useFmt()
const dir = useDirectory()
const cols = 'grid-cols-[42px_minmax(170px,1.4fr)_104px_minmax(150px,1fr)_108px_90px_84px_92px_124px_64px]'

interface Block { key: string, title: string, sub: string, locked: boolean, section: RuleSection | null, rules: RuleView[], layerSize: number }

const blocks = computed<Block[]>(() => {
  const baselineRules = props.baseline.flatMap(s => s.rules)
  const zoneRules = props.sections.flatMap(s => s.rules)
  return [
    ...props.baseline.map((s, i) => ({ key: `b-${i}`, title: s.name ? `${t('rules.baseline')} · ${s.name}` : t('rules.baseline'), sub: t('rules.baselineSub'), locked: true, section: s, rules: s.rules, layerSize: baselineRules.length })),
    ...props.sections.map((s, i) => ({ key: `z-${i}`, title: s.name ?? t('rules.noSection'), sub: t('rules.zoneSub', { zone: props.zoneName }), locked: false, section: s, rules: s.rules, layerSize: zoneRules.length })),
  ]
})

const maxHits = computed(() => Math.max(1, ...[...props.baseline, ...props.sections].flatMap(s => s.rules).map(r => r.hits)))

function action(r: RuleView) {
  const observe = r.action === 'deny' && r.layer.type === 'zone' && props.zoneMode === 'observe'
  if (observe) return { label: t('action.observe'), fg: 'var(--obs)', bg: 'var(--obs-bg)', bar: 'var(--obs)' }
  return r.action === 'deny'
    ? { label: t('action.deny'), fg: 'var(--ko)', bg: 'var(--ko-bg)', bar: 'var(--ko)' }
    : { label: t('action.accept'), fg: 'var(--ok)', bg: 'var(--ok-bg)', bar: 'var(--ok)' }
}

function tag(r: RuleView): { label: string, cls: string } | null {
  if (r.locked_by) return { label: t('rules.tag.locked', { by: r.locked_by.name }), cls: 'bg-warn-bg text-warn' }
  if (r.pending_change) return { label: t(`rules.tag.${r.pending_change}`), cls: 'bg-pri-bg text-pri' }
  if (!r.enabled) return { label: t('rules.tag.disabled'), cls: 'bg-sub text-text3' }
  if (r.expired) return { label: t('rules.tag.expired'), cls: 'bg-warn-bg text-warn' }
  if (r.hits === 0 && !r.last_hit_at) return { label: t('rules.tag.unused'), cls: 'bg-sub text-text2' }
  return null
}

const names = (ids: string[], name: (id: string) => string | null) => ids.map(id => name(id) ?? id.slice(0, 8)).join(', ')
const sources = (r: RuleView) => names(r.sources, dir.zoneName) || t('rules.all')
const destinations = (r: RuleView) => names(r.destinations, dir.objectName) || t('rules.anyDest')
const service = (r: RuleView) => (r.data_classes.length ? t('rules.classService', { name: names(r.data_classes, dir.dataClassName) }) : names(r.services, dir.serviceName) || t('rules.any'))
</script>

<template>
  <div class="afw-card overflow-x-auto">
    <div class="min-w-[1080px]">
      <div
        class="afw-th grid gap-[10px] border-b border-line px-[14px] py-2"
        :class="cols"
      >
        <span>{{ t('rules.col.n') }}</span><span>{{ t('rules.col.name') }}</span><span>{{ t('rules.col.source') }}</span><span>{{ t('rules.col.destination') }}</span><span>{{ t('rules.col.service') }}</span><span>{{ t('rules.col.action') }}</span><span>{{ t('rules.col.track') }}</span><span>{{ t('rules.col.expiry') }}</span><span>{{ t('rules.col.hits') }}</span><span />
      </div>
      <template
        v-for="b in blocks"
        :key="b.key"
      >
        <div class="flex items-center gap-2 border-b border-line bg-sub px-[14px] py-[7px] text-xs font-[650]">
          <UIcon
            v-if="b.locked"
            name="i-lucide-lock"
            class="size-3"
          />
          <span>{{ b.title }}</span><span class="font-normal text-text3">{{ b.sub }}</span>
          <span class="flex-1" />
          <button
            v-if="editable && b.section"
            type="button"
            class="afw-ghost rounded px-1.5 text-[11px] font-medium text-text3"
            :aria-label="t('rules.sectionForm.editAria')"
            @click="emit('section', b.section)"
          >
            <UIcon
              name="i-lucide-pencil"
              class="size-3"
            />
          </button>
        </div>
        <div
          v-for="r in b.rules"
          :key="r.id"
          class="grid items-center gap-[10px] border-b border-line px-[14px] py-2"
          :class="[cols, r.pending_change ? 'bg-pri-bg' : '']"
          :data-testid="`rule-${r.number}`"
        >
          <span
            class="font-mono text-xs font-semibold"
            :class="r.layer.type === 'baseline' ? 'text-obs' : ''"
          >{{ r.number }}</span>
          <span class="flex min-w-0 flex-col leading-[1.3]">
            <span class="flex min-w-0 items-center gap-1.5">
              <span
                class="truncate font-semibold"
                :class="r.expired || !r.enabled ? 'line-through' : ''"
              >{{ r.name }}</span>
              <span
                v-if="tag(r)"
                class="flex-none rounded px-[5px] text-[10.5px] font-bold"
                :class="tag(r)!.cls"
                :data-testid="`rule-tag-${r.number}`"
              >{{ tag(r)!.label }}</span>
            </span>
            <span class="truncate text-[11px] text-text3">{{ r.comment }}</span>
          </span>
          <span class="truncate text-xs">{{ sources(r) }}</span>
          <span class="truncate font-mono text-[11.5px]">{{ destinations(r) }}</span>
          <span class="truncate text-xs">{{ service(r) }}</span>
          <span><span
            class="inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-[650]"
            :style="{ color: action(r).fg, background: action(r).bg }"
          >{{ action(r).label }}</span></span>
          <span class="text-xs text-text2">{{ t(`track.${r.track}`) }}</span>
          <span
            class="text-xs"
            :class="r.expired ? 'font-bold text-warn' : r.expires_at ? '' : 'text-text3'"
          >{{ r.expires_at ? fmt.date(r.expires_at) : '—' }}</span>
          <span class="flex flex-col gap-[3px]">
            <span class="flex justify-between gap-1.5 text-[11.5px]">
              <span class="font-mono font-semibold">{{ r.pending_change === 'create' ? '—' : fmt.num(r.hits) }}</span>
              <span class="text-text3">{{ r.pending_change === 'create' ? t('rules.notInstalled') : fmt.rel(r.last_hit_at) }}</span>
            </span>
            <span class="h-1 overflow-hidden rounded-sm bg-sub"><span
              class="block h-1"
              :style="{ width: `${Math.round((r.hits / maxHits) * 100)}%`, background: action(r).bar }"
            /></span>
          </span>
          <span
            v-if="editable"
            class="flex justify-end gap-0.5"
          >
            <UDropdownMenu
              :items="[[
                { label: t('common.edit'), icon: 'i-lucide-pencil', onSelect: () => emit('edit', r) },
                { label: t('rules.moveUp'), icon: 'i-lucide-arrow-up', disabled: r.position <= 1, onSelect: () => emit('move', r, r.position - 1) },
                { label: t('rules.moveDown'), icon: 'i-lucide-arrow-down', disabled: r.position >= b.layerSize, onSelect: () => emit('move', r, r.position + 1) },
                { label: t('common.delete'), icon: 'i-lucide-trash-2', color: 'error', onSelect: () => emit('remove', r) },
              ]]"
            >
              <button
                type="button"
                class="afw-ghost flex size-6 items-center justify-center rounded"
                :aria-label="t('rules.actionsFor', { name: r.name })"
                :data-testid="`rule-menu-${r.number}`"
              >
                <UIcon
                  name="i-lucide-ellipsis"
                  class="size-[14px]"
                />
              </button>
            </UDropdownMenu>
          </span>
          <span v-else />
        </div>
      </template>
      <div
        class="grid items-center gap-[10px] px-[14px] py-2 text-text2"
        :class="cols"
        data-testid="rule-cleanup"
      >
        <span class="font-mono text-xs font-semibold">{{ cleanupNumber }}</span>
        <span class="flex flex-col leading-[1.3]">
          <span class="font-semibold">{{ t('rules.cleanup') }}</span>
          <span class="text-[11px] text-text3">{{ zoneMode === 'observe' ? t('rules.cleanupObserveSub') : t('rules.cleanupSub') }}</span>
        </span>
        <span class="text-xs">{{ zoneName }}</span>
        <span class="font-mono text-[11.5px]">{{ t('rules.anyDest') }}</span>
        <span class="text-xs">{{ t('rules.any') }}</span>
        <span><span
          class="inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-[650]"
          :style="zoneMode === 'observe' ? { color: 'var(--obs)', background: 'var(--obs-bg)' } : { color: 'var(--ko)', background: 'var(--ko-bg)' }"
        >{{ zoneMode === 'observe' ? t('action.observe') : t('action.deny') }}</span></span>
        <span class="text-xs">{{ t('track.log') }}</span>
        <span class="text-xs text-text3">—</span>
        <span />
        <span />
      </div>
    </div>
  </div>
</template>
