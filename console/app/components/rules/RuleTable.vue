<script setup lang="ts">
import type { RuleView, ZoneMode } from '~/api/types'

const props = defineProps<{
  baseline: RuleView[]
  rules: RuleView[]
  zoneName: string
  zoneMode: ZoneMode
}>()

const { t } = useI18n()
const fmt = useFmt()
const cols = 'grid-cols-[42px_minmax(170px,1.4fr)_104px_minmax(150px,1fr)_108px_90px_80px_84px_92px_124px]'

interface Section { key: string, title: string, sub: string, locked: boolean, rules: RuleView[] }

const sections = computed<Section[]>(() => {
  const out: Section[] = [{ key: 'baseline', title: t('rules.baseline'), sub: t('rules.baselineSub'), locked: true, rules: props.baseline }]
  for (const r of props.rules) {
    const key = r.section ?? '—'
    let s = out.find(x => x.key === key)
    if (!s) {
      s = key === 'cleanup'
        ? { key, title: t('rules.cleanup'), sub: props.zoneMode === 'observe' ? t('rules.cleanupObserveSub') : t('rules.cleanupSub'), locked: false, rules: [] }
        : { key, title: key, sub: t('rules.zoneSub', { zone: props.zoneName }), locked: false, rules: [] }
      out.push(s)
    }
    s.rules.push(r)
  }
  return out
})

function action(r: RuleView) {
  const observe = r.action === 'deny' && r.layer.type === 'zone' && props.zoneMode === 'observe'
  if (observe) return { label: t('action.observe'), fg: 'var(--obs)', bg: 'var(--obs-bg)', bar: 'var(--obs)' }
  return r.action === 'deny'
    ? { label: t('action.deny'), fg: 'var(--ko)', bg: 'var(--ko-bg)', bar: 'var(--ko)' }
    : { label: t('action.accept'), fg: 'var(--ok)', bg: 'var(--ok-bg)', bar: 'var(--ok)' }
}

function tag(r: RuleView): { label: string, cls: string } | null {
  if (r.in_session) return { label: t('rules.tag.session'), cls: 'bg-pri-bg text-pri' }
  if (r.expired) return { label: t('rules.tag.expired'), cls: 'bg-warn-bg text-warn' }
  if (r.hits === 0 && !r.last_hit_at) return { label: t('rules.tag.unused'), cls: 'bg-sub text-text2' }
  return null
}

const service = (r: RuleView) => (r.data_class_names.length ? t('rules.classService', { name: r.data_class_names.join(', ') }) : r.service_names.join(', ') || t('rules.any'))
const comment = (r: RuleView) => r.comment || (r.previous_number ? t('rules.wasRule', { n: r.previous_number }) : '')
</script>

<template>
  <div class="afw-card overflow-x-auto">
    <div class="min-w-[1080px]">
      <div
        class="afw-th grid gap-[10px] border-b border-line px-[14px] py-2"
        :class="cols"
      >
        <span>{{ t('rules.col.n') }}</span><span>{{ t('rules.col.name') }}</span><span>{{ t('rules.col.source') }}</span><span>{{ t('rules.col.destination') }}</span><span>{{ t('rules.col.service') }}</span><span>{{ t('rules.col.action') }}</span><span>{{ t('rules.col.https') }}</span><span>{{ t('rules.col.track') }}</span><span>{{ t('rules.col.expiry') }}</span><span>{{ t('rules.col.hits') }}</span>
      </div>
      <template
        v-for="sec in sections"
        :key="sec.key"
      >
        <div class="flex items-center gap-2 border-b border-line bg-sub px-[14px] py-[7px] text-xs font-[650]">
          <UIcon
            v-if="sec.locked"
            name="i-lucide-lock"
            class="size-3"
          />
          <span>{{ sec.title }}</span><span class="font-normal text-text3">{{ sec.sub }}</span>
        </div>
        <div
          v-for="r in sec.rules"
          :key="r.id"
          class="grid items-center gap-[10px] border-b border-line px-[14px] py-2"
          :class="[cols, r.in_session ? 'bg-pri-bg' : '']"
          :data-testid="`rule-${r.number}`"
        >
          <span
            class="font-mono text-xs font-semibold"
            :class="r.number.startsWith('S') ? 'text-obs' : ''"
          >{{ r.number }}</span>
          <span class="flex min-w-0 flex-col leading-[1.3]">
            <span class="flex min-w-0 items-center gap-1.5">
              <span
                class="truncate font-semibold"
                :class="r.expired ? 'line-through' : ''"
              >{{ r.name }}</span>
              <span
                v-if="tag(r)"
                class="flex-none rounded px-[5px] text-[10.5px] font-bold"
                :class="tag(r)!.cls"
              >{{ tag(r)!.label }}</span>
            </span>
            <span class="truncate text-[11px] text-text3">{{ comment(r) }}</span>
          </span>
          <span class="truncate text-xs">{{ r.source_names.join(', ') || t('rules.all') }}</span>
          <span class="truncate font-mono text-[11.5px]">{{ r.destination_names.join(', ') || t('rules.anyDest') }}</span>
          <span class="truncate text-xs">{{ service(r) }}</span>
          <span><span
            class="inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-[650]"
            :style="{ color: action(r).fg, background: action(r).bg }"
          >{{ action(r).label }}</span></span>
          <span class="text-xs text-text2">{{ r.inspection === 'inspect' ? t('rules.decrypted') : r.inspection === 'bypass' ? t('rules.bypass') : '—' }}</span>
          <span class="text-xs text-text2">{{ t(`track.${r.track}`) }}</span>
          <span
            class="text-xs"
            :class="r.expired ? 'font-bold text-warn' : r.expires_at ? '' : 'text-text3'"
          >{{ r.expires_at ? fmt.date(r.expires_at) : '—' }}</span>
          <span class="flex flex-col gap-[3px]">
            <span class="flex justify-between gap-1.5 text-[11.5px]">
              <span class="font-mono font-semibold">{{ r.in_session ? '—' : fmt.num(r.hits) }}</span>
              <span class="text-text3">{{ r.in_session ? t('rules.notInstalled') : fmt.rel(r.last_hit_at) }}</span>
            </span>
            <span class="h-1 overflow-hidden rounded-sm bg-sub"><span
              class="block h-1"
              :style="{ width: `${Math.round(r.hit_ratio * 100)}%`, background: action(r).bar }"
            /></span>
          </span>
        </div>
      </template>
    </div>
  </div>
</template>
