<script setup lang="ts">
import type { Zone, ZoneMode } from '~/api/types'
import { newUuid } from '~/utils/forms'

/** Create or edit a zone (mode enforce/observe, delegation to the admin MCP). */
const props = defineProps<{ zone?: Zone | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [Zone] }>()
const { t } = useI18n()
const api = useApi()
const { busy, error, run } = usePolicyWrite()

const form = reactive({ name: '', comment: '', mode: 'observe' as ZoneMode, delegated: false })
watch(open, (o) => {
  if (!o) return
  error.value = null
  const z = props.zone
  Object.assign(form, { name: z?.name ?? '', comment: z?.comment ?? '', mode: z?.mode ?? 'observe', delegated: z?.delegated_to_mcp ?? false })
}, { immediate: true })
const modes = computed(() => (['enforce', 'observe'] as ZoneMode[]).map(m => ({ label: t(`zone.mode.${m}`), value: m })))

async function submit() {
  const body: Zone = { id: props.zone?.id ?? newUuid(), name: form.name.trim(), comment: form.comment, mode: form.mode, delegated_to_mcp: form.delegated }
  const saved = await run(sid => (props.zone ? api.zones.update(sid, body) : api.zones.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="zone ? t('zone.form.edit', { name: zone.name }) : t('zone.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="zone-name"
    >
      <UInput
        id="zone-name"
        v-model="form.name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('zone.form.mode')"
      :hint="t('zone.form.modeHint')"
      for="zone-mode"
    >
      <USelect
        id="zone-mode"
        v-model="form.mode"
        :items="modes"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('zone.form.delegated')"
      :hint="t('zone.form.delegatedHint')"
    >
      <USwitch v-model="form.delegated" />
    </FormsFormField>
    <FormsFormField
      :label="t('form.comment')"
      for="zone-comment"
    >
      <UTextarea
        id="zone-comment"
        v-model="form.comment"
        :rows="2"
        size="sm"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
