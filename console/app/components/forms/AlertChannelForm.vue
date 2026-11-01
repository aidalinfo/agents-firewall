<script setup lang="ts">
import type { AlertChannel, AlertChannelKind, Severity } from '~/api/types'
import { newUuid } from '~/utils/forms'

/** Create or edit an alert channel (webhook, Teams, Pulse Chat). Not part of a policy session. */
const props = defineProps<{ channel?: AlertChannel | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [AlertChannel] }>()
const { t } = useI18n()
const api = useApi()
const { busy, error, plain } = usePolicyWrite()

const draft = reactive({ name: '', kind: 'webhook' as AlertChannelKind })
const url = ref('')
const severity = ref<Severity>('warning')
const enabled = ref(true)
watch(open, (o) => {
  if (!o) return
  error.value = null
  const c = props.channel
  Object.assign(draft, { name: c?.name ?? '', kind: c?.kind ?? 'webhook' })
  url.value = c?.url ?? ''
  severity.value = c?.min_severity ?? 'warning'
  enabled.value = c?.enabled ?? true
}, { immediate: true })
const kinds = computed(() => (['webhook', 'teams', 'pulse_chat'] as AlertChannelKind[]).map(k => ({ label: t(`alerts.channelKind.${k}`), value: k })))
const severities = computed(() => (['info', 'warning', 'critical'] as Severity[]).map(s => ({ label: t(`severity.${s}`), value: s })))

async function submit() {
  const body: AlertChannel = { id: props.channel?.id ?? newUuid(), name: draft.name.trim(), kind: draft.kind, url: url.value.trim(), min_severity: severity.value, enabled: enabled.value }
  const saved = await plain(() => (props.channel ? api.alertChannels.update(body) : api.alertChannels.create(body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="channel ? t('channels.form.edit', { name: channel.name }) : t('channels.form.create')"
    :busy="busy"
    :error="error"
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="ch-name"
    >
      <UInput
        id="ch-name"
        v-model="draft.name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('channels.kindLabel')"
      for="ch-kind"
    >
      <USelect
        id="ch-kind"
        v-model="draft.kind"
        :items="kinds"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('channels.url')"
      :hint="channel ? t('channels.urlMasked') : undefined"
      for="ch-url"
    >
      <UInput
        id="ch-url"
        v-model="url"
        type="url"
        size="sm"
        class="font-mono"
        placeholder="https://"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('channels.minSeverity')"
      for="ch-sev"
    >
      <USelect
        id="ch-sev"
        v-model="severity"
        :items="severities"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField :label="t('channels.enabled')">
      <USwitch v-model="enabled" />
    </FormsFormField>
  </FormsFormShell>
</template>
