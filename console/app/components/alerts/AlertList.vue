<script setup lang="ts">
import type { Alert } from '~/api/types'

defineProps<{ alerts: Alert[] }>()
const emit = defineEmits<{ changed: [] }>()

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const problem = useProblem()
const dir = useDirectory()
onMounted(() => void dir.ensure())

function sev(a: Alert) {
  if (a.acknowledged) return { key: 'resolved', cls: 'bg-ok-bg text-ok' }
  if (a.event.severity === 'critical') return { key: 'critical', cls: 'bg-ko-bg text-ko' }
  if (a.event.severity === 'warning') return { key: 'warning', cls: 'bg-warn-bg text-warn' }
  return { key: 'info', cls: 'bg-sub text-text2' }
}

async function ack(a: Alert) {
  try {
    await api.acknowledgeAlert(a.event.id)
    emit('changed')
  }
  catch (e) {
    problem.notify(e)
  }
}

async function capture(a: Alert) {
  if (!a.event.agent_id) return
  try {
    await api.startCapture({ agent_id: a.event.agent_id, duration_secs: 300 })
    toast.add({ title: t('flow.captureStarted', { agent: dir.agentName(a.event.agent_id) ?? '' }), icon: 'i-lucide-radio' })
  }
  catch (e) {
    problem.notify(e)
  }
}

const context = (a: Alert) => [dir.agentName(a.event.agent_id), dir.gatewayName(a.gateway_id)].filter(Boolean).join(' · ')
</script>

<template>
  <ul class="m-0 list-none p-0">
    <li
      v-for="a in alerts"
      :key="a.event.id"
      class="flex flex-col gap-1.5 border-b border-line px-[14px] py-3"
      :style="{ opacity: a.acknowledged ? 0.75 : 1 }"
      :data-testid="`alert-${a.event.kind}`"
    >
      <div class="flex items-center gap-2">
        <span
          class="rounded px-1.5 py-px text-[10.5px] font-bold tracking-[.04em] uppercase"
          :class="sev(a).cls"
        >{{ t(`alerts.severity.${sev(a).key}`) }}</span>
        <strong class="min-w-0 flex-1 text-[12.5px]">{{ t(`alerts.kind.${a.event.kind}`) }}</strong>
        <span class="text-[11px] whitespace-nowrap text-text3">{{ fmt.rel(a.event.at) }}</span>
      </div>
      <span class="text-[12.5px] text-text2">{{ a.event.summary }}</span>
      <span class="text-[11.5px] text-text3">{{ context(a) }}<template v-if="a.acknowledged_by"> · {{ t('alerts.ackBy', { who: a.acknowledged_by.name }) }}</template></span>
      <div
        v-if="!a.acknowledged"
        class="flex flex-wrap gap-1.5"
      >
        <NuxtLink
          :to="{ path: '/', query: dir.agentName(a.event.agent_id) ? { q: `agent:${dir.agentName(a.event.agent_id)}` } : {} }"
          class="flex h-7 items-center rounded-md border border-line2 px-[10px] text-xs font-semibold no-underline"
          style="color: var(--text)"
        >{{ t('alerts.seeFlows') }}</NuxtLink>
        <button
          v-if="a.event.agent_id"
          type="button"
          class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
          @click="capture(a)"
        >
          {{ t('alerts.pcap') }}
        </button>
        <button
          type="button"
          class="h-7 rounded-md border-0 bg-transparent px-[10px] text-xs font-medium text-text2"
          :data-testid="`ack-${a.event.kind}`"
          @click="ack(a)"
        >
          {{ t('alerts.ack') }}
        </button>
      </div>
    </li>
  </ul>
</template>
