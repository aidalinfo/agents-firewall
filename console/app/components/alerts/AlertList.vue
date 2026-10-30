<script setup lang="ts">
import type { AlertView } from '~/api/types'

defineProps<{ alerts: AlertView[] }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()

function sev(a: AlertView) {
  if (a.resolved) return { key: 'resolved', cls: 'bg-ok-bg text-ok' }
  if (a.severity === 'critical') return { key: 'critical', cls: 'bg-ko-bg text-ko' }
  if (a.severity === 'warning') return { key: 'warning', cls: 'bg-warn-bg text-warn' }
  return { key: 'info', cls: 'bg-sub text-text2' }
}

async function ack(a: AlertView) {
  await api.acknowledgeAlert(a.id)
  emit('changed')
}

async function capture(a: AlertView) {
  if (!a.agent_id) return
  await api.startCapture({ agent_id: a.agent_id, duration_secs: 300 })
  toast.add({ title: t('flow.captureStarted', { agent: a.agent_name ?? '' }), icon: 'i-lucide-radio' })
}

const open = (a: AlertView) => !a.resolved && a.severity !== 'info'
</script>

<template>
  <ul class="m-0 list-none p-0">
    <li
      v-for="a in alerts"
      :key="a.id"
      class="flex flex-col gap-1.5 border-b border-line px-[14px] py-3"
      :style="{ opacity: a.resolved ? 0.75 : 1 }"
      :data-testid="`alert-${a.kind}`"
    >
      <div class="flex items-center gap-2">
        <span
          class="rounded px-1.5 py-px text-[10.5px] font-bold tracking-[.04em] uppercase"
          :class="sev(a).cls"
        >{{ t(`alerts.severity.${sev(a).key}`) }}</span>
        <strong class="min-w-0 flex-1 text-[12.5px]">{{ t(`alerts.kind.${a.kind}`) }}</strong>
        <span class="text-[11px] whitespace-nowrap text-text3">{{ fmt.rel(a.at) }}</span>
      </div>
      <span class="text-[12.5px] text-text2">{{ a.summary }}</span>
      <span class="text-[11.5px] text-text3">{{ a.context }}<template v-if="a.acknowledged_by"> · {{ t('alerts.ackBy', { who: a.acknowledged_by }) }}</template></span>
      <div
        v-if="open(a)"
        class="flex flex-wrap gap-1.5"
      >
        <NuxtLink
          :to="{ path: '/', query: a.agent_name ? { q: `agent:${a.agent_name}` } : {} }"
          class="flex h-7 items-center rounded-md border border-line2 px-[10px] text-xs font-semibold no-underline"
          style="color: var(--text)"
        >{{ t('alerts.seeFlows') }}</NuxtLink>
        <button
          type="button"
          class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
          @click="capture(a)"
        >
          {{ t('alerts.pcap') }}
        </button>
        <button
          type="button"
          class="h-7 rounded-md border-0 bg-transparent px-[10px] text-xs font-medium text-text2"
          :data-testid="`ack-${a.kind}`"
          @click="ack(a)"
        >
          {{ t('alerts.ack') }}
        </button>
      </div>
    </li>
  </ul>
</template>
