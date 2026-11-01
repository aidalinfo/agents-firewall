<script setup lang="ts">
import type { TraceStep, Verdict } from '~/api/types'

/** Evaluation trace computed by the API (the console never evaluates a rule). */
const props = defineProps<{ steps: TraceStep[], verdict: Verdict, observed: boolean }>()
const { t } = useI18n()

/** Collapses runs of non-matching rules of one layer, as the mockup shows them. */
const rows = computed(() => {
  const out: { key: string, label: string, name: string, step: TraceStep, count: number }[] = []
  for (const s of props.steps) {
    const last = out.at(-1)
    if (s.outcome !== 'matched' && last && last.step.outcome === s.outcome && last.step.layer === s.layer && s.rule_number != null && last.step.rule_number != null) {
      last.count++
      last.label = `${String(last.label).split('–')[0]}–${s.rule_number}`
      last.name = t(s.layer === 'baseline' ? 'trace.baselineRange' : 'trace.zoneRange', { n: last.count })
      continue
    }
    const [num, ...rest] = s.rule_label.split(' · ')
    out.push({ key: `${s.rule_id ?? s.rule_label}-${out.length}`, label: s.rule_number != null ? num! : '', name: s.rule_number != null ? rest.join(' · ') : s.rule_label, step: s, count: 1 })
  }
  return out
})

function look(s: TraceStep) {
  if (s.outcome !== 'matched') return { icon: '·', fg: 'var(--text3)', nameFg: 'var(--text3)', bg: 'transparent' }
  if (props.observed) return { icon: '◐', fg: 'var(--obs)', nameFg: 'var(--text)', bg: 'var(--obs-bg)' }
  if (props.verdict === 'deny') return { icon: '✕', fg: 'var(--ko)', nameFg: 'var(--text)', bg: 'var(--ko-bg)' }
  return { icon: '✓', fg: 'var(--ok)', nameFg: 'var(--text)', bg: 'var(--ok-bg)' }
}

function result(s: TraceStep) {
  if (s.outcome === 'skipped') return t('trace.result.skipped')
  if (s.outcome === 'not_matched') return t('trace.result.no_match')
  return props.observed ? t('trace.result.observe') : t(`trace.result.${props.verdict === 'deny' ? 'deny' : 'accept'}`)
}
</script>

<template>
  <ol class="m-0 list-none py-1.5">
    <li
      v-for="r in rows"
      :key="r.key"
      class="grid grid-cols-[14px_54px_minmax(0,1fr)_auto] items-center gap-2 px-[10px] py-[3px] font-mono text-[11.5px]"
      :style="{ background: look(r.step).bg }"
      :title="r.step.reason"
      :data-testid="`trace-${r.label || r.step.rule_label}`"
    >
      <span
        class="font-bold"
        :style="{ color: look(r.step).fg }"
      >{{ look(r.step).icon }}</span>
      <span
        class="font-semibold"
        :style="{ color: look(r.step).fg, opacity: r.step.layer === 'baseline' ? 1 : undefined }"
      >{{ r.label }}</span>
      <span
        class="truncate font-sans text-xs"
        :style="{ color: look(r.step).nameFg }"
      >{{ r.name }}</span>
      <span
        class="text-[11px]"
        :style="{ color: look(r.step).fg }"
      >{{ result(r.step) }}</span>
    </li>
  </ol>
</template>
