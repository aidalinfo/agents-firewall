<script setup lang="ts">
const { t } = useI18n()
const { gateways, installedRevision, p95, stats } = useShell()
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
        {{ g.name }}<template v-if="g.status_detail"> · {{ t(`gateways.detail.${g.status_detail}`) }}</template>
      </span>
    </NuxtLink>
    <span v-if="installedRevision">{{ t('status.revision', { n: installedRevision }) }}</span>
    <span v-if="p95 != null">{{ t('status.latency', { ms: p95 }) }}</span>
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
