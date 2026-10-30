<script setup lang="ts">
import type { TraceStep } from '~/api/types'

defineProps<{ steps: TraceStep[] }>()
const { t } = useI18n()

function look(s: TraceStep) {
  if (s.result === 'no_match') return { icon: '·', fg: 'var(--text3)', nameFg: 'var(--text3)', bg: 'transparent' }
  if (s.result === 'deny') return { icon: '✕', fg: 'var(--ko)', nameFg: 'var(--text)', bg: 'var(--ko-bg)' }
  if (s.result === 'observe') return { icon: '◐', fg: 'var(--obs)', nameFg: 'var(--text)', bg: 'var(--obs-bg)' }
  return { icon: '✓', fg: 'var(--ok)', nameFg: 'var(--text)', bg: 'var(--ok-bg)' }
}

function name(s: TraceStep) {
  if (!s.range) return s.name
  return s.range.layer === 'baseline' ? t('trace.baseline') : t('trace.zoneRules', { n: s.range.count, zone: s.range.zone ?? '' })
}
</script>

<template>
  <ol class="m-0 list-none py-1.5">
    <li
      v-for="s in steps"
      :key="s.label"
      class="grid grid-cols-[14px_54px_minmax(0,1fr)_auto] items-center gap-2 px-[10px] py-[3px] font-mono text-[11.5px]"
      :style="{ background: look(s).bg }"
      :data-testid="`trace-${s.label}`"
    >
      <span
        class="font-bold"
        :style="{ color: look(s).fg }"
      >{{ look(s).icon }}</span>
      <span
        class="font-semibold"
        :style="{ color: look(s).fg }"
      >{{ s.label }}</span>
      <span
        class="truncate font-sans text-xs"
        :style="{ color: look(s).nameFg }"
      >{{ name(s) }}</span>
      <span
        class="text-[11px]"
        :style="{ color: look(s).fg }"
      >{{ t(`trace.result.${s.result}`) }}</span>
    </li>
  </ol>
</template>
