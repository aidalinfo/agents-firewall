<script setup lang="ts">
defineProps<{
  title: string
  prefix?: string
  subtitle?: string
}>()
</script>

<template>
  <header class="flex flex-wrap items-center gap-3 border-b border-line bg-panel px-4 py-[10px]">
    <span
      v-if="prefix"
      class="font-mono text-[12.5px] text-text3"
    >{{ prefix }}</span>
    <h1 class="m-0 text-[15px] font-[650]">
      {{ title }}
    </h1>
    <span
      v-if="subtitle"
      class="text-xs text-text3"
    >{{ subtitle }}</span>
    <slot />
    <span class="flex-1" />
    <slot name="actions" />
    <ShellPageHeaderTools />
  </header>
</template>
