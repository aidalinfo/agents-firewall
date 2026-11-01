<script setup lang="ts">
import type { Agent } from '~/api/types'

/** Moves an agent to another zone (an agent update in the session: rules follow the zone). */
const props = defineProps<{ agent: Agent | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [Agent] }>()
const { t } = useI18n()
const api = useApi()
const dir = useDirectory()
const { busy, error, run } = usePolicyWrite()

const zoneId = ref('')
watch(open, (o) => {
  if (!o) return
  error.value = null
  zoneId.value = props.agent?.zone_id ?? ''
  void dir.ensure()
}, { immediate: true })
const zones = computed(() => dir.data.value.zones.map(z => ({ label: `${z.name}${z.mode === 'observe' ? ` · ${t('zone.observation')}` : ''}`, value: z.id })))

async function submit() {
  const a = props.agent
  if (!a) return
  // The agent as the session sees it (draft), with only its zone changed.
  const saved = await run(async sid => api.agents.update(sid, { ...(await api.agents.get(a.id)), zone_id: zoneId.value }))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="t('agents.move.title', { name: agent?.name ?? '' })"
    :description="t('agents.move.description')"
    :busy="busy"
    :error="error"
    :submit-label="t('agents.move.submit')"
    @submit="submit"
  >
    <FormsFormField
      :label="t('agents.move.zone')"
      for="agent-zone"
    >
      <USelect
        id="agent-zone"
        v-model="zoneId"
        :items="zones"
        size="sm"
        class="w-full"
        data-testid="agent-zone"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
