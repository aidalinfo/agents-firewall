<script setup lang="ts">
import type { RuleView } from '~/api/types'

/**
 * Sections are a property of the rules (consecutive rules sharing a name). Creating or renaming
 * one sets `section` on the chosen rules of the layer, one rule update each.
 */
const props = defineProps<{ rules: RuleView[], current?: string | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [] }>()
const { t } = useI18n()
const api = useApi()
const { busy, error, run } = usePolicyWrite()

const name = ref('')
const chosen = ref<string[]>([])
watch(open, (o) => {
  if (!o) return
  error.value = null
  name.value = props.current ?? ''
  chosen.value = props.rules.filter(r => props.current != null && r.section === props.current).map(r => r.id)
}, { immediate: true })
const items = computed(() => props.rules.map(r => ({ label: `${r.number} · ${r.name}`, value: r.id })))

async function submit() {
  const section = name.value.trim() || null
  const ok = await run(async (sid) => {
    for (const r of props.rules) {
      const inSection = chosen.value.includes(r.id)
      const target = inSection ? section : (r.section === props.current && props.current != null ? null : r.section)
      if (target === r.section) continue
      const { number: _n, hits: _h, last_hit_at: _l, expired: _e, locked_by: _b, pending_change: _p, ...rule } = r
      await api.rules.update(sid, { ...rule, section: target })
    }
    return true
  })
  if (ok) {
    open.value = false
    emit('saved')
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="current ? t('rules.sectionForm.edit', { name: current }) : t('rules.sectionForm.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="section-name"
    >
      <UInput
        id="section-name"
        v-model="name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('rules.sectionForm.rules')"
      :hint="t('rules.sectionForm.rulesHint')"
      for="section-rules"
    >
      <FormsMultiSelect
        id="section-rules"
        v-model="chosen"
        :items="items"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
