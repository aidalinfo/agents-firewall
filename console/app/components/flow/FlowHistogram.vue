<script setup lang="ts">
import type { FlowStats } from '~/api/types'

export type Segment = 'all' | 'allow' | 'deny' | 'alert'

const props = defineProps<{
  stats: FlowStats | null
  segment: Segment
}>()
const emit = defineEmits<{
  'update:segment': [Segment]
  'range': [{ from: string, to: string }]
}>()

const { t } = useI18n()
const fmt = useFmt()

const segments = computed(() => {
  const s = props.stats
  return ([
    ['all', s?.total, 'var(--text3)'],
    ['allow', s?.allowed, 'var(--bar)'],
    ['deny', s?.denied, 'var(--ko)'],
    ['alert', s?.alerts, 'var(--warn)'],
  ] as const).map(([key, n, swatch]) => ({ key, n: fmt.num(n ?? null), swatch }))
})

const max = computed(() => Math.max(1, ...(props.stats?.histogram ?? []).map(h => h.allowed + h.denied)))
const bars = computed(() => (props.stats?.histogram ?? []).map((h) => {
  const scale = 60 / Math.max(max.value, 60)
  const dim = (props.segment === 'deny' || props.segment === 'alert') && h.denied === 0
  return { ...h, ok: Math.round(h.allowed * scale), ko: Math.round(h.denied * scale), dim, tip: t('journal.histTip', { time: fmt.hm(h.at), ok: h.allowed, ko: h.denied }) }
}))
const ticks = computed(() => {
  const h = props.stats?.histogram ?? []
  return [0, 15, 30, 45].map(i => fmt.hm(h[i]?.at)).concat(t('journal.now'))
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
  const h = props.stats?.histogram
  if (!d || !h || d.a === d.b) return
  const [a, b] = d.a < d.b ? [d.a, d.b] : [d.b, d.a]
  emit('range', { from: h[a]!.at, to: new Date(new Date(h[b]!.at).getTime() + 60_000).toISOString() })
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
