<script setup lang="ts">
import type { FlowSummary } from '~/api/types'
import { verdictTone } from '~/utils/format'

defineProps<{
  flows: FlowSummary[]
  selected: string | null
  loading?: boolean
}>()
const emit = defineEmits<{ select: [string] }>()

const { t } = useI18n()
const fmt = useFmt()
const cols = 'grid-cols-[92px_84px_124px_minmax(200px,1.5fr)_118px_minmax(140px,1fr)_62px]'

function tone(f: FlowSummary) {
  const v = verdictTone(f)
  return v === 'ok' ? { fg: 'var(--ok)', bg: 'var(--ok-bg)', key: 'allow' } : v === 'obs' ? { fg: 'var(--obs)', bg: 'var(--obs-bg)', key: 'observed' } : { fg: 'var(--ko)', bg: 'var(--ko-bg)', key: 'deny' }
}
</script>

<template>
  <div class="afw-card overflow-x-auto">
    <div class="min-w-[760px]">
      <div
        class="grid gap-[10px] border-b border-line px-[14px] py-2 font-mono text-[10.5px] text-text3"
        :class="cols"
      >
        <span>{{ t('journal.col.time') }}</span>
        <span>{{ t('journal.col.verdict') }}</span>
        <span>{{ t('journal.col.agent') }}</span>
        <span>{{ t('journal.col.destination') }}</span>
        <span>{{ t('journal.col.rule') }}</span>
        <span>{{ t('journal.col.tool') }}</span>
        <span class="text-right">{{ t('journal.col.out') }}</span>
      </div>
      <button
        v-for="f in flows"
        :key="f.id"
        type="button"
        class="afw-row grid w-full items-center gap-[10px] border-0 border-b border-line bg-transparent px-[14px] py-[7px] text-left"
        :class="cols"
        :aria-current="f.id === selected ? 'true' : 'false'"
        :data-testid="`flow-row-${f.id}`"
        @click="emit('select', f.id)"
      >
        <span class="font-mono text-[11.5px] text-text3">{{ fmt.time(f.started_at, true) }}</span>
        <span
          class="flex items-center gap-[7px] font-mono text-[11.5px] font-semibold"
          :style="{ color: tone(f).fg }"
        >
          <span
            class="size-[7px] rounded-full"
            :style="{ background: tone(f).fg, boxShadow: `0 0 0 3px ${tone(f).bg}` }"
          />{{ t(`verdict.${tone(f).key}`) }}
        </span>
        <span class="flex min-w-0 flex-col leading-[1.25]">
          <span class="truncate font-mono text-xs font-semibold">{{ f.agent_name ?? '—' }}</span>
          <span class="font-mono text-[10.5px] text-text3">@{{ f.zone_name ?? '—' }}</span>
        </span>
        <span class="flex min-w-0 flex-col leading-[1.3]">
          <span class="truncate font-mono text-xs font-medium">{{ f.domain ?? f.dst }}</span>
          <span class="truncate font-mono text-[10.5px] text-text3"><span class="text-pri">{{ f.method }}</span> {{ f.path }}</span>
        </span>
        <span class="flex min-w-0 items-center gap-1.5">
          <span
            class="rounded bg-sub px-[5px] font-mono text-[11px] font-semibold"
            :style="{ color: f.decision.layer === 'baseline' ? 'var(--obs)' : 'var(--text)' }"
          >#{{ f.rule_label }}</span>
          <span class="truncate text-[11.5px] text-text2">{{ f.decision.rule_name }}</span>
        </span>
        <span class="flex min-w-0 items-center gap-1.5">
          <span class="truncate font-mono text-[11.5px] text-text2">{{ f.tool ?? '—' }}</span>
          <span
            v-if="f.correlation?.confidence === 'uncertain'"
            :title="t('flow.uncertain')"
            class="flex-none rounded bg-warn-bg px-1 font-mono text-[10px] font-bold text-warn"
          >≈</span>
        </span>
        <span class="text-right font-mono text-[11.5px] text-text2">{{ fmt.bytes(f.bytes_out) }}</span>
      </button>
      <div
        v-if="!flows.length && !loading"
        class="px-[14px] py-6 text-center text-text3"
      >
        {{ t('journal.empty') }}
      </div>
      <div class="flex flex-wrap items-center gap-[14px] px-[14px] py-[9px] font-mono text-[11px] text-text3">
        <span>{{ t('journal.shown', { n: flows.length }) }}</span>
        <span class="flex-1" />
        <span><kbd class="rounded-[3px] border border-line2 px-1">j</kbd> <kbd class="rounded-[3px] border border-line2 px-1">k</kbd> {{ t('journal.kbd.navigate') }}</span>
        <span><kbd class="rounded-[3px] border border-line2 px-1">a</kbd> {{ t('journal.kbd.allow') }}</span>
        <span><kbd class="rounded-[3px] border border-line2 px-1">c</kbd> {{ t('journal.kbd.curl') }}</span>
        <span><kbd class="rounded-[3px] border border-line2 px-1">?</kbd> {{ t('shortcuts.title') }}</span>
      </div>
    </div>
  </div>
</template>
