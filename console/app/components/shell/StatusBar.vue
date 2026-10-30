<script setup lang="ts">
const { t, te } = useI18n()
const { gateways, policy, stats } = useShell()
const detail = (d: string) => (te(`gateways.detail.${d}`) ? t(`gateways.detail.${d}`) : d)
const emit = defineEmits<{ shortcuts: [] }>()
</script>

<template>
  <footer class="flex flex-wrap items-center gap-4 border-t border-line bg-panel px-[14px] py-[5px] font-mono text-[11px] text-text3">
    <NuxtLink
      to="/gateways"
      class="flex flex-wrap items-center gap-3 no-underline"
      style="color: var(--text3)"
    >
      <span
        v-for="g in gateways.data.value"
        :key="g.id"
        class="flex items-center gap-[5px]"
        :class="g.status === 'online' ? '' : g.status === 'degraded' ? 'text-warn' : 'text-ko'"
      >
        <span
          class="size-1.5 rounded-full"
          :class="g.status === 'online' ? 'bg-ok' : g.status === 'degraded' ? 'bg-warn' : 'bg-ko'"
        />
        {{ g.name }}<template v-if="g.status_detail"> · {{ detail(g.status_detail) }}</template>
      </span>
    </NuxtLink>
    <span
      v-if="policy.data.value?.installed_revision != null"
      data-testid="status-revision"
    >{{ t('status.revision', { n: policy.data.value.installed_revision, k: policy.data.value.gateways_on_revision, total: policy.data.value.gateways_total }) }}</span>
    <span v-if="policy.data.value?.latency_p95_ms != null">{{ t('status.latency', { ms: policy.data.value.latency_p95_ms }) }}</span>
    <span v-if="stats.data.value">{{ t('status.ingestion', { n: stats.data.value.per_minute }) }}</span>
    <span class="flex-1" />
    <button
      type="button"
      class="border-0 bg-transparent font-mono text-[11px] text-text3"
      @click="emit('shortcuts')"
    >
      <kbd class="rounded-[3px] border border-line2 px-1">?</kbd> {{ t('shortcuts.title') }}
    </button>
  </footer>
</template>
