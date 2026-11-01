<script setup lang="ts">
import type { CreatedApiToken, Role } from '~/api/types'
import { dateToIso } from '~/utils/forms'

/** Creates an API token; its secret is shown once, then only its metadata remains. */
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [CreatedApiToken] }>()
const { t } = useI18n()
const api = useApi()
const dir = useDirectory()
const copy = useCopy()
const { busy, error, plain } = usePolicyWrite()

const form = reactive({ name: '', role: 'viewer' as Role, agent: '', expires: '' })
const created = ref<CreatedApiToken | null>(null)
watch(open, (o) => {
  if (!o) return
  error.value = null
  created.value = null
  void dir.ensure()
  Object.assign(form, { name: '', role: 'viewer', agent: '', expires: '' })
}, { immediate: true })
const roles = computed(() => (['admin', 'auditor', 'viewer', 'mcp_agent', 'agent_plugin'] as Role[]).map(r => ({ label: t(`role.${r}`), value: r })))
const agents = computed(() => dir.data.value.agents.map(a => ({ label: a.name, value: a.id })))
const needsAgent = computed(() => form.role === 'mcp_agent' || form.role === 'agent_plugin')

async function submit() {
  if (created.value) {
    open.value = false
    return
  }
  const res = await plain(() => api.createToken({ name: form.name.trim(), role: form.role, agent_id: needsAgent.value && form.agent ? form.agent : null, expires_at: dateToIso(form.expires) }))
  if (res) {
    created.value = res
    emit('saved', res)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="t('tokens.form.create')"
    :busy="busy"
    :error="error"
    :submit-label="created ? t('common.close') : t('tokens.form.submit')"
    @submit="submit"
  >
    <template v-if="created">
      <UAlert
        color="warning"
        variant="subtle"
        icon="i-lucide-key-round"
        :title="t('tokens.secretOnce')"
      />
      <div class="flex items-center gap-2 rounded-lg border border-line bg-code px-3 py-2 font-mono text-xs">
        <span
          class="min-w-0 flex-1 break-all"
          data-testid="token-secret"
        >{{ created.secret }}</span>
        <UButton
          size="xs"
          color="neutral"
          variant="outline"
          icon="i-lucide-copy"
          @click="copy(created.secret, t('tokens.secret'))"
        />
      </div>
    </template>
    <template v-else>
      <FormsFormField
        :label="t('form.name')"
        for="tok-name"
      >
        <UInput
          id="tok-name"
          v-model="form.name"
          size="sm"
        />
      </FormsFormField>
      <FormsFormField
        :label="t('tokens.role')"
        for="tok-role"
      >
        <USelect
          id="tok-role"
          v-model="form.role"
          :items="roles"
          size="sm"
          class="w-full"
        />
      </FormsFormField>
      <FormsFormField
        v-if="needsAgent"
        :label="t('tokens.agent')"
        for="tok-agent"
      >
        <USelect
          id="tok-agent"
          v-model="form.agent"
          :items="agents"
          size="sm"
          class="w-full"
        />
      </FormsFormField>
      <FormsFormField
        :label="t('tokens.expires')"
        for="tok-exp"
      >
        <UInput
          id="tok-exp"
          v-model="form.expires"
          type="date"
          size="sm"
          class="w-44"
        />
      </FormsFormField>
    </template>
  </FormsFormShell>
</template>
