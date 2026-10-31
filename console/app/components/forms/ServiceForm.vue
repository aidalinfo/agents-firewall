<script setup lang="ts">
import type { AppProto, L4Proto, Service } from '~/api/types'
import { formatPorts, newUuid, parsePorts } from '~/utils/forms'

/** Create or edit a service (protocol, ports, optional application match). */
const props = defineProps<{ service?: Service | null }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [Service] }>()
const { t } = useI18n()
const api = useApi()
const { busy, error, run } = usePolicyWrite()

const form = reactive({ name: '', comment: '', protocol: 'tcp' as L4Proto, ports: '', app: 'none' as AppProto | 'none', methods: '', paths: '' })

watch(open, (o) => {
  if (!o) return
  error.value = null
  const s = props.service
  Object.assign(form, {
    name: s?.name ?? '',
    comment: s?.comment ?? '',
    protocol: s?.protocol ?? 'tcp',
    ports: s ? formatPorts(s.ports) : '',
    app: s?.app?.proto ?? 'none',
    methods: s?.app?.methods.join(', ') ?? '',
    paths: s?.app?.path_prefixes.join(', ') ?? '',
  })
}, { immediate: true })

const protocols = computed(() => (['tcp', 'udp', 'any'] as L4Proto[]).map(p => ({ label: p.toUpperCase(), value: p })))
const apps = computed(() => (['none', 'http', 'https', 'dns', 'ssh', 'tls', 'other'] as const).map(p => ({ label: p === 'none' ? t('services.noApp') : p.toUpperCase(), value: p })))
const list = (v: string) => v.split(',').map(x => x.trim()).filter(Boolean)

async function submit() {
  const ports = parsePorts(form.ports)
  if (ports === null) {
    error.value = t('services.badPorts')
    return
  }
  const body: Service = {
    id: props.service?.id ?? newUuid(),
    name: form.name.trim(),
    comment: form.comment,
    protocol: form.protocol,
    ports,
    app: form.app === 'none' ? null : { proto: form.app, methods: list(form.methods).map(m => m.toUpperCase()), path_prefixes: list(form.paths) },
  }
  const saved = await run(sid => (props.service ? api.services.update(sid, body) : api.services.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="service ? t('services.form.edit', { name: service.name }) : t('services.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="svc-name"
    >
      <UInput
        id="svc-name"
        v-model="form.name"
        size="sm"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('services.protocol')"
      for="svc-proto"
    >
      <USelect
        id="svc-proto"
        v-model="form.protocol"
        :items="protocols"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('services.ports')"
      :hint="t('services.portsHint')"
      for="svc-ports"
    >
      <UInput
        id="svc-ports"
        v-model="form.ports"
        placeholder="443, 8000-8100"
        size="sm"
        class="font-mono"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('services.app')"
      for="svc-app"
    >
      <USelect
        id="svc-app"
        v-model="form.app"
        :items="apps"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <template v-if="form.app === 'http' || form.app === 'https'">
      <FormsFormField
        :label="t('services.methods')"
        for="svc-methods"
      >
        <UInput
          id="svc-methods"
          v-model="form.methods"
          placeholder="GET, POST"
          size="sm"
          class="font-mono"
        />
      </FormsFormField>
      <FormsFormField
        :label="t('services.paths')"
        for="svc-paths"
      >
        <UInput
          id="svc-paths"
          v-model="form.paths"
          placeholder="/api/v1/ingest"
          size="sm"
          class="font-mono"
        />
      </FormsFormField>
    </template>
    <FormsFormField
      :label="t('form.comment')"
      for="svc-comment"
    >
      <UTextarea
        id="svc-comment"
        v-model="form.comment"
        :rows="2"
        size="sm"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
