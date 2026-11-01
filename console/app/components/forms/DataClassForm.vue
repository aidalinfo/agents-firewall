<script setup lang="ts">
import type { DataCategory, DataClass } from '~/api/types'
import { formatDetectors, newUuid, parseDetectors } from '~/utils/forms'

/** Create or edit a data class (detectors applied by the gateways, EF-24). */
const props = defineProps<{ dataClass?: DataClass | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [DataClass] }>()
const { t } = useI18n()
const api = useApi()
const { busy, error, run } = usePolicyWrite()

const form = reactive({ name: '', comment: '', category: 'secret' as DataCategory, detectors: '' })
watch(open, (o) => {
  if (!o) return
  error.value = null
  const d = props.dataClass
  Object.assign(form, { name: d?.name ?? '', comment: d?.comment ?? '', category: d?.category ?? 'secret', detectors: d ? formatDetectors(d.detectors) : '' })
}, { immediate: true })
const categories = computed(() => (['secret', 'infra', 'commercial', 'personal', 'custom'] as DataCategory[]).map(c => ({ label: t(`dataClasses.category.${c}`), value: c })))

async function submit() {
  const detectors = parseDetectors(form.detectors)
  if (detectors === null) {
    error.value = t('dataClasses.badDetectors')
    return
  }
  const body: DataClass = { id: props.dataClass?.id ?? newUuid(), name: form.name.trim(), comment: form.comment, category: form.category, detectors }
  const saved = await run(sid => (props.dataClass ? api.dataClasses.update(sid, body) : api.dataClasses.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="dataClass ? t('dataClasses.form.edit', { name: dataClass.name }) : t('dataClasses.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="dc-name"
    >
      <UInput
        id="dc-name"
        v-model="form.name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('dataClasses.categoryLabel')"
      for="dc-cat"
    >
      <USelect
        id="dc-cat"
        v-model="form.category"
        :items="categories"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('dataClasses.detectors')"
      :hint="t('dataClasses.detectorsHint')"
      for="dc-det"
    >
      <UTextarea
        id="dc-det"
        v-model="form.detectors"
        :rows="4"
        size="sm"
        class="font-mono"
        placeholder="builtin:aws_access_key&#10;regex:numero-client=CL-\d{6}"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('form.comment')"
      for="dc-comment"
    >
      <UTextarea
        id="dc-comment"
        v-model="form.comment"
        :rows="2"
        size="sm"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
