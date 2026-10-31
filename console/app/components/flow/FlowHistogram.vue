<script setup lang="ts">
import type { FlowStats } from '~/api/types'

export type Segment = 'all' | 'allow' | 'deny' | 'observed'

const props = defineProps<{
  stats: FlowStats | null
  segment: Segment
  /** Selected period (null for a dragged range): picks the tick format. */
  period?: string | null
}>()
const emit = defineEmits<{
  'update:segment': [Segment]
  'range': [{ from: string, to: string }]
}>()

const { t } = useI18n()
const fmt = useFmt()

const BUCKET_MS = { '1m': 60_000, '5m': 300_000, '1h': 3_600_000 } as const

const segments = computed(() => {
  const s = props.stats
  return ([
    ['all', s?.total, 'var(--text3)'],
    ['allow', s?.allow, 'var(--bar)'],
    ['deny', s?.deny, 'var(--ko)'],
    ['observed', s?.observed, 'var(--obs)'],
  ] as const).map(([key, n, swatch]) => ({ key, n: fmt.num(n ?? null), swatch }))
})

const points = computed(() => props.stats?.points ?? [])
const max = computed(() => Math.max(1, ...points.value.map(h => h.allow + h.deny + h.observed)))
const bars = computed(() => points.value.map((h) => {
  const scale = 60 / Math.max(max.value, 60)
  const dim = (props.segment === 'deny' && h.deny === 0) || (props.segment === 'observed' && h.observed === 0)
  return { ...h, ok: Math.round(h.allow * scale), ko: Math.round(h.deny * scale), obs: Math.round(h.observed * scale), dim, tip: t('journal.histTip', { time: fmt.hm(h.at), ok: h.allow, ko: h.deny, obs: h.observed }) }
}))
const ticks = computed(() => {
  const h = points.value
  if (!h.length) return []
  const label = (iso: string) => (props.period === '7d' ? fmt.dateTime(iso) : fmt.hm(iso))
  return [0, 0.25, 0.5, 0.75].map(r => label(h[Math.floor(r * h.length)]!.at)).concat(t('journal.now'))
})

const drag = ref<{ a: number, b: number } | null>(null)
function down(i: number) {
  drag.value = { a: i, b: i }
}
function over(i: number) {
  if (drag.value) drag.value.b = i
}
function up() {
  const d = drag.value
  drag.value = null
  const h = points.value
  if (!d || !h.length || d.a === d.b || !props.stats) return
  const [a, b] = d.a < d.b ? [d.a, d.b] : [d.b, d.a]
  emit('range', { from: h[a]!.at, to: new Date(new Date(h[b]!.at).getTime() + BUCKET_MS[props.stats.bucket]).toISOString() })
}
const inDrag = (i: number) => !!drag.value && i >= Math.min(drag.value.a, drag.value.b) && i <= Math.max(drag.value.a, drag.value.b)
</script>

<template>
  <div class="afw-card flex flex-col gap-2 px-3 pt-[10px] pb-2">
    <div class="flex flex-wrap items-center gap-1.5">
      <button
        v-for="sg in segments"
        :key="sg.key"
        type="button"
        class="flex h-[26px] items-center gap-[7px] rounded-md border px-[9px] text-xs font-medium text-text"
        :class="segment === sg.key ? 'border-line2 bg-sub' : 'border-transparent bg-transparent'"
        :aria-pressed="segment === sg.key"
        :data-testid="`segment-${sg.key}`"
        @click="emit('update:segment', sg.key)"
      >
        <span
          class="size-2 rounded-[2px]"
          :style="{ background: sg.swatch }"
        />
        {{ t(`journal.segment.${sg.key}`) }}
        <span class="font-mono text-[11.5px] text-text2">{{ sg.n }}</span>
      </button>
      <span class="flex-1" />
      <span class="font-mono text-[11px] text-text3">{{ t('journal.dragHint') }}</span>
    </div>
    <div
      role="img"
      :aria-label="t('journal.histAria')"
      class="flex h-16 select-none items-end gap-[2px]"
      @pointerleave="drag = null"
      @pointerup="up"
    >
      <div
        v-for="(b, i) in bars"
        :key="b.at"
        class="afw-hbar flex h-16 flex-1 flex-col justify-end"
        :style="{ opacity: b.dim ? 0.35 : 1, background: inDrag(i) ? 'var(--pri-bg)' : undefined }"
        :title="b.tip"
        @pointerdown.prevent="down(i)"
        @pointerenter="over(i)"
      >
        <div
          class="rounded-t-[1px] bg-ko"
          :style="{ height: `${b.ko}px` }"
        />
        <div
          class="bg-obs"
          :style="{ height: `${b.obs}px` }"
        />
        <div
          class="bg-bar"
          :style="{ height: `${b.ok}px` }"
        />
      </div>
    </div>
    <div class="flex justify-between font-mono text-[10.5px] text-text3">
      <span
        v-for="(tk, i) in ticks"
        :key="i"
      >{{ tk }}</span>
    </div>
  </div>
</template>
