<script setup lang="ts">
const props = defineProps<{ current?: string }>()
const api = useApi()
const { t } = useI18n()
const agents = useAsyncData('agent-tabs', () => api.listAgents(), { default: () => [] })
const items = computed(() => agents.data.value.map(a => ({ id: a.agent.id, name: a.agent.name })))
</script>

<template>
  <span
    class="text-[13px] text-text3"
  >{{ t('nav.agents') }}</span><span
    aria-hidden="true"
    class="text-text3"
  >/</span>
  <div
    role="tablist"
    :aria-label="t('agents.tabs')"
    class="flex flex-wrap gap-1"
  >
    <NuxtLink
      v-for="a in items"
      :key="a.id"
      :to="`/agents/${a.id}`"
      role="tab"
      :aria-selected="a.id === props.current"
      class="flex h-7 items-center rounded-md px-[10px] font-mono text-xs no-underline"
      :class="a.id === props.current ? 'bg-text font-semibold text-bg hover:text-bg' : 'border border-line text-text2'"
    >
      {{ a.name }}
    </NuxtLink>
  </div>
</template>
