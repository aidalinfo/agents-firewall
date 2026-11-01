<script setup lang="ts">
defineProps<{ label: string, code: string }>()
const { t } = useI18n()
const copy = useCopy()
</script>

<template>
  <div class="flex flex-col overflow-hidden rounded-lg border border-line bg-code">
    <div class="flex items-center justify-between border-b border-line px-[10px] py-1.5 font-mono text-[10.5px] text-text3">
      <span>{{ label }}</span>
      <button
        type="button"
        class="afw-ghost rounded px-1.5 font-mono text-[10.5px] text-text2"
        @click="copy(code)"
      >
        {{ t('common.copy') }}
      </button>
    </div>
    <pre
      class="m-0 whitespace-pre-wrap px-[10px] py-[9px] font-mono text-[11.5px] leading-[1.6] text-text"
      data-testid="cli-snippet"
    >{{ code }}</pre>
  </div>
</template>
