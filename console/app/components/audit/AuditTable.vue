<script setup lang="ts">
import type { AuditEntry } from '~/api/types'

defineProps<{ entries: AuditEntry[] }>()
const { t, te } = useI18n()
const fmt = useFmt()
const cols = 'grid-cols-[80px_150px_92px_70px_170px_minmax(200px,1fr)_100px]'

const kindCls = (k: AuditEntry['actor']['kind']) => (k === 'agent' ? 'bg-obs-bg text-obs' : k === 'system' ? 'bg-sub text-text2' : 'bg-pri-bg text-pri')
const action = (a: string) => (te(`audit.action.${a.replace(/\./g, '_')}`) ? t(`audit.action.${a.replace(/\./g, '_')}`) : a)
const short = (h: string) => (h ? `${h.slice(0, 4)}…${h.slice(-4)}` : '—')
const refused = (e: AuditEntry) => e.action.endsWith('denied') || e.action.endsWith('refused')
</script>

<template>
  <div class="min-w-[900px]">
    <div
      class="afw-th grid gap-[10px] border-y border-line px-[14px] py-1.5"
      :class="cols"
    >
      <span>{{ t('audit.col.time') }}</span><span>{{ t('audit.col.author') }}</span><span>{{ t('audit.col.interface') }}</span><span>{{ t('audit.col.session') }}</span><span>{{ t('audit.col.action') }}</span><span>{{ t('audit.col.target') }}</span><span>{{ t('audit.col.hash') }}</span>
    </div>
    <div
      v-for="e in entries"
      :key="e.seq"
      class="grid items-center gap-[10px] border-b border-line px-[14px] py-[7px] text-xs"
      :class="[cols, refused(e) ? 'bg-ko-bg' : '']"
      :data-testid="`audit-${e.action}`"
    >
      <span class="font-mono text-[11.5px] text-text2">{{ fmt.time(e.at) }}</span>
      <span class="flex min-w-0 items-center gap-1.5">
        <span
          class="flex-none rounded px-[5px] text-[10px] font-bold uppercase"
          :class="kindCls(e.actor.kind)"
        >{{ t(`audit.kind.${e.actor.kind}`) }}</span>
        <span class="truncate">{{ e.actor.name }}</span>
      </span>
      <span class="text-text2">{{ t(`audit.iface.${e.interface}`) }}</span>
      <span class="font-mono text-[11.5px] text-text3">{{ e.session_id?.slice(0, 8) ?? '—' }}</span>
      <span
        class="font-semibold"
        :class="refused(e) ? 'text-ko' : ''"
      >{{ action(e.action) }}</span>
      <span class="truncate font-mono text-[11.5px] text-text2">{{ e.target }}</span>
      <span
        class="font-mono text-[11px] text-text3"
        :title="e.hash"
      >{{ short(e.hash) }}</span>
    </div>
  </div>
</template>
