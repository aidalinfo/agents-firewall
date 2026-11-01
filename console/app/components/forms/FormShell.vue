<script setup lang="ts">
/** Modal frame shared by every create/edit form: title, API error, cancel / submit. */
defineProps<{
  title: string
  description?: string
  busy?: boolean
  error?: string | null
  submitLabel?: string
  /** Shown under the title: the change goes to the caller's session (nothing applied before install). */
  inSession?: boolean
  danger?: boolean
}>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ submit: [] }>()
const { t } = useI18n()
</script>

<template>
  <UModal
    v-model:open="open"
    :title="title"
    :description="description ?? (inSession ? t('form.inSession') : undefined)"
    :ui="{ content: 'max-w-xl' }"
  >
    <template #body>
      <form
        class="flex flex-col gap-3"
        data-testid="form"
        @submit.prevent="emit('submit')"
      >
        <slot />
        <UAlert
          v-if="error"
          color="error"
          variant="subtle"
          icon="i-lucide-circle-alert"
          :title="error"
          data-testid="form-error"
        />
        <div class="flex justify-end gap-2 pt-1">
          <UButton
            color="neutral"
            variant="outline"
            @click="open = false"
          >
            {{ t('common.cancel') }}
          </UButton>
          <UButton
            type="submit"
            :loading="busy"
            :color="danger ? 'error' : 'primary'"
            class="font-[650]"
            data-testid="form-submit"
          >
            {{ submitLabel ?? t('form.save') }}
          </UButton>
        </div>
      </form>
    </template>
  </UModal>
</template>
