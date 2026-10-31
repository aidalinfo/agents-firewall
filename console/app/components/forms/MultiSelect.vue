<script setup lang="ts">
/** Multiple choice among API resources (ids), labelled by name. */
defineProps<{ items: { label: string, value: string }[], placeholder?: string, id?: string }>()
const model = defineModel<string[]>({ default: () => [] })
</script>

<template>
  <USelectMenu
    :id="id"
    v-model="model"
    :items="items"
    value-key="value"
    multiple
    :placeholder="placeholder"
    class="w-full"
    size="sm"
  />
</template>
