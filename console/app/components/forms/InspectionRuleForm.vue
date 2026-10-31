<script setup lang="ts">
import type { InspectionAction, InspectionRule } from '~/api/types'
import { newUuid } from '~/utils/forms'

/** Create or edit a TLS inspection rule (inspect or bypass; default when nothing matches: inspect). */
const props = defineProps<{ rule?: InspectionRule | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [InspectionRule] }>()
const { t } = useI18n()
const api = useApi()
const dir = useDirectory()
const { busy, error, run } = usePolicyWrite()

const form = reactive({ name: '', position: 1, zones: [] as string[], destinations: [] as string[], action: 'bypass' as InspectionAction })
watch(open, (o) => {
  if (!o) return
  error.value = null
  void dir.ensure()
  const r = props.rule
  Object.assign(form, { name: r?.name ?? '', position: r?.position ?? 1, zones: r ? [...r.zones] : [], destinations: r ? [...r.destinations] : [], action: r?.action ?? 'bypass' })
}, { immediate: true })
const actions = computed(() => (['inspect', 'bypass'] as InspectionAction[]).map(a => ({ label: t(`inspection.action.${a}`), value: a })))
const zoneItems = computed(() => dir.data.value.zones.map(z => ({ label: z.name, value: z.id })))
const objectItems = computed(() => dir.data.value.objects.map(o => ({ label: o.name, value: o.id })))

async function submit() {
  const body: InspectionRule = { id: props.rule?.id ?? newUuid(), name: form.name.trim(), position: Math.max(1, Math.trunc(Number(form.position) || 1)), zones: [...form.zones], destinations: [...form.destinations], action: form.action }
  const saved = await run(sid => (props.rule ? api.inspectionRules.update(sid, body) : api.inspectionRules.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="rule ? t('inspection.form.edit', { name: rule.name }) : t('inspection.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="insp-name"
    >
      <UInput
        id="insp-name"
        v-model="form.name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.form.position')"
      for="insp-pos"
    >
      <UInput
        id="insp-pos"
        v-model.number="form.position"
        type="number"
        min="1"
        size="sm"
        class="w-28"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('inspection.zones')"
      for="insp-zones"
    >
      <FormsMultiSelect
        id="insp-zones"
        v-model="form.zones"
        :items="zoneItems"
        :placeholder="t('rules.all')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.destination')"
      for="insp-dst"
    >
      <FormsMultiSelect
        id="insp-dst"
        v-model="form.destinations"
        :items="objectItems"
        :placeholder="t('rules.anyDest')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.action')"
      for="insp-action"
    >
      <USelect
        id="insp-action"
        v-model="form.action"
        :items="actions"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
