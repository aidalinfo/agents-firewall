<script setup lang="ts">
import type { Action, Rule, Track } from '~/api/types'
import { dateToIso, isoToDate, newUuid } from '~/utils/forms'

/**
 * Create or edit a rule of the baseline or of a zone layer. The position is the rank in the
 * layer (1 = top); the API places the rule and renumbers the layer.
 */
const props = defineProps<{ rule?: Rule | null, layerZone?: string | null, section?: string | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [Rule] }>()
const { t } = useI18n()
const api = useApi()
const dir = useDirectory()
const { busy, error, run } = usePolicyWrite()

const BASELINE = 'baseline'
const form = reactive({
  name: '', layer: BASELINE, section: '', position: 1, sources: [] as string[], destinations: [] as string[], services: [] as string[],
  dataClasses: [] as string[], action: 'accept' as Action, track: 'detailed' as Track, expires: '', comment: '', enabled: true,
})

watch(open, (o) => {
  if (!o) return
  error.value = null
  void dir.ensure()
  const r = props.rule
  const layer = r ? (r.layer.type === 'baseline' ? BASELINE : r.layer.zone_id) : (props.layerZone ?? BASELINE)
  Object.assign(form, {
    name: r?.name ?? '',
    layer,
    section: r?.section ?? props.section ?? '',
    position: r?.position ?? 1,
    sources: r ? [...r.sources] : layer === BASELINE ? [] : [layer],
    destinations: r ? [...r.destinations] : [],
    services: r ? [...r.services] : [],
    dataClasses: r ? [...r.data_classes] : [],
    action: r?.action ?? 'accept',
    track: r?.track ?? 'detailed',
    expires: isoToDate(r?.expires_at),
    comment: r?.comment ?? '',
    enabled: r?.enabled ?? true,
  })
}, { immediate: true })

const layers = computed(() => [{ label: t('rules.baseline'), value: BASELINE }, ...dir.data.value.zones.map(z => ({ label: t('rules.form.zoneLayer', { zone: z.name }), value: z.id }))])
const zoneItems = computed(() => dir.data.value.zones.map(z => ({ label: z.name, value: z.id })))
const objectItems = computed(() => dir.data.value.objects.map(o => ({ label: o.name, value: o.id })))
const serviceItems = computed(() => dir.data.value.services.map(s => ({ label: s.name, value: s.id })))
const classItems = computed(() => dir.data.value.dataClasses.map(c => ({ label: c.name, value: c.id })))
const actions = computed(() => (['accept', 'deny'] as Action[]).map(a => ({ label: t(`action.${a}`), value: a })))
const tracks = computed(() => (['detailed', 'log', 'capture', 'none'] as Track[]).map(v => ({ label: t(`track.${v}Long`), value: v })))

async function submit() {
  const body: Rule = {
    id: props.rule?.id ?? newUuid(),
    name: form.name.trim(),
    layer: form.layer === BASELINE ? { type: 'baseline' } : { type: 'zone', zone_id: form.layer },
    section: form.section.trim() || null,
    position: Math.max(1, Math.trunc(Number(form.position) || 1)),
    sources: [...form.sources],
    destinations: [...form.destinations],
    services: [...form.services],
    data_classes: [...form.dataClasses],
    action: form.action,
    track: form.track,
    expires_at: dateToIso(form.expires),
    comment: form.comment,
    enabled: form.enabled,
  }
  const saved = await run(sid => (props.rule ? api.rules.update(sid, body) : api.rules.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="rule ? t('rules.form.edit', { name: rule.name }) : t('rules.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="rule-name"
    >
      <UInput
        id="rule-name"
        v-model="form.name"
        size="sm"
        data-testid="rule-name"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.form.layer')"
      for="rule-layer"
    >
      <USelect
        id="rule-layer"
        v-model="form.layer"
        :items="layers"
        size="sm"
        class="w-full"
        :disabled="!!rule"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.form.position')"
      :hint="t('rules.form.positionHint')"
      for="rule-pos"
    >
      <UInput
        id="rule-pos"
        v-model.number="form.position"
        type="number"
        min="1"
        size="sm"
        class="w-28"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.section')"
      for="rule-section"
    >
      <UInput
        id="rule-section"
        v-model="form.section"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.source')"
      :hint="t('rules.form.sourcesHint')"
      for="rule-src"
    >
      <FormsMultiSelect
        id="rule-src"
        v-model="form.sources"
        :items="zoneItems"
        :placeholder="t('rules.all')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.destination')"
      for="rule-dst"
    >
      <FormsMultiSelect
        id="rule-dst"
        v-model="form.destinations"
        :items="objectItems"
        :placeholder="t('rules.anyDest')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.service')"
      for="rule-svc"
    >
      <FormsMultiSelect
        id="rule-svc"
        v-model="form.services"
        :items="serviceItems"
        :placeholder="t('rules.any')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.form.dataClasses')"
      for="rule-dc"
    >
      <FormsMultiSelect
        id="rule-dc"
        v-model="form.dataClasses"
        :items="classItems"
        :placeholder="t('rules.form.noDataClass')"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.action')"
      for="rule-action"
    >
      <USelect
        id="rule-action"
        v-model="form.action"
        :items="actions"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.track')"
      for="rule-track"
    >
      <USelect
        id="rule-track"
        v-model="form.track"
        :items="tracks"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.col.expiry')"
      for="rule-exp"
    >
      <UInput
        id="rule-exp"
        v-model="form.expires"
        type="date"
        size="sm"
        class="w-44"
      />
    </FormsFormField>
    <FormsFormField :label="t('rules.form.enabled')">
      <USwitch v-model="form.enabled" />
    </FormsFormField>
    <FormsFormField
      :label="t('form.comment')"
      for="rule-comment"
    >
      <UTextarea
        id="rule-comment"
        v-model="form.comment"
        :rows="2"
        size="sm"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
