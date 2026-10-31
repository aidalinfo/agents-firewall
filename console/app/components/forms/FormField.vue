<script setup lang="ts">
defineProps<{ label: string, hint?: string, for?: string }>()
</script>

<template>
  <div class="grid grid-cols-[130px_minmax(0,1fr)] items-start gap-x-3 text-[12.5px]">
    <label
      :for="$props.for"
      class="pt-1.5 text-text2"
    >{{ label }}</label>
    <div class="flex min-w-0 flex-col gap-1">
      <slot />
      <span
        v-if="hint"
        class="text-[11px] text-text3"
      >{{ hint }}</span>
    </div>
  </div>
</template>
