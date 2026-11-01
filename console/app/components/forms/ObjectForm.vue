<script setup lang="ts">
import type { DestCategory, NetObject, NetObjectSpec } from '~/api/types'
import { newUuid } from '~/utils/forms'

/** Create or edit a network object (EF-44). Values are sent as typed: the API validates them. */
const props = defineProps<{ object?: NetObject | null, /** Prefill from `object` but create a new one. */ clone?: boolean }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ saved: [NetObject] }>()
const { t } = useI18n()
const api = useApi()
const dir = useDirectory()
const { busy, error, run } = usePolicyWrite()

type Kind = NetObjectSpec['type']
const form = reactive({ name: '', comment: '', category: 'none' as DestCategory | 'none', kind: 'domain' as Kind, value: '', end: '', members: [] as string[] })

watch(open, (o) => {
  if (!o) return
  error.value = null
  const v = props.object
  const s = v?.spec
  Object.assign(form, {
    name: v?.name ?? '',
    comment: v?.comment ?? '',
    category: v?.category ?? 'none',
    kind: s?.type ?? 'domain',
    value: s?.type === 'domain' ? s.pattern : s?.type === 'host' ? s.ip : s?.type === 'network' ? s.cidr : s?.type === 'range' ? s.start : '',
    end: s?.type === 'range' ? s.end : '',
    members: s?.type === 'group' ? [...s.members] : [],
  })
}, { immediate: true })

const kinds = computed(() => (['domain', 'host', 'network', 'range', 'group', 'any'] as Kind[]).map(k => ({ label: t(`objects.kind.${k}`), value: k })))
const categories = computed(() => (['none', 'llm_provider', 'cloud_metadata', 'internal'] as const).map(c => ({ label: t(`objects.category.${c}`), value: c })))
const memberItems = computed(() => dir.data.value.objects.filter(o => o.id !== props.object?.id).map(o => ({ label: o.name, value: o.id })))

function spec(): NetObjectSpec {
  const v = form.value.trim()
  switch (form.kind) {
    case 'domain': return { type: 'domain', pattern: v }
    case 'host': return { type: 'host', ip: v }
    case 'network': return { type: 'network', cidr: v }
    case 'range': return { type: 'range', start: v, end: form.end.trim() }
    case 'group': return { type: 'group', members: [...form.members] }
    default: return { type: 'any' }
  }
}

async function submit() {
  const editing = props.object && !props.clone
  const body: NetObject = { id: editing ? props.object!.id : newUuid(), name: form.name.trim(), comment: form.comment, category: form.category === 'none' ? null : form.category, spec: spec() }
  const saved = await run(sid => (editing ? api.objects.update(sid, body) : api.objects.create(sid, body)))
  if (saved) {
    open.value = false
    emit('saved', saved)
  }
}

const placeholder = computed(() => ({ domain: 'api.exemple.com · *.exemple.com', host: '10.0.4.12', network: '10.0.0.0/16', range: '10.0.0.10', group: '', any: '' })[form.kind])
</script>

<template>
  <FormsFormShell
    v-model:open="open"
    :title="object && !clone ? t('objects.form.edit', { name: object.name }) : t('objects.form.create')"
    :busy="busy"
    :error="error"
    in-session
    @submit="submit"
  >
    <FormsFormField
      :label="t('form.name')"
      for="obj-name"
    >
      <UInput
        id="obj-name"
        v-model="form.name"
        size="sm"
        data-testid="obj-name"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('objects.form.kind')"
      for="obj-kind"
    >
      <USelect
        id="obj-kind"
        v-model="form.kind"
        :items="kinds"
        size="sm"
        class="w-full"
        data-testid="obj-kind"
      />
    </FormsFormField>
    <FormsFormField
      v-if="form.kind !== 'group' && form.kind !== 'any'"
      :label="form.kind === 'range' ? t('objects.form.start') : t('objects.form.value')"
      for="obj-value"
    >
      <UInput
        id="obj-value"
        v-model="form.value"
        :placeholder="placeholder"
        size="sm"
        class="font-mono"
        data-testid="obj-value"
      />
    </FormsFormField>
    <FormsFormField
      v-if="form.kind === 'range'"
      :label="t('objects.form.end')"
      for="obj-end"
    >
      <UInput
        id="obj-end"
        v-model="form.end"
        size="sm"
        class="font-mono"
      />
    </FormsFormField>
    <FormsFormField
      v-if="form.kind === 'group'"
      :label="t('objects.form.members')"
      for="obj-members"
    >
      <FormsMultiSelect
        id="obj-members"
        v-model="form.members"
        :items="memberItems"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('objects.form.category')"
      :hint="t('objects.form.categoryHint')"
      for="obj-cat"
    >
      <USelect
        id="obj-cat"
        v-model="form.category"
        :items="categories"
        size="sm"
        class="w-full"
      />
    </FormsFormField>
    <FormsFormField
      :label="t('form.comment')"
      for="obj-comment"
    >
      <UTextarea
        id="obj-comment"
        v-model="form.comment"
        :rows="2"
        size="sm"
      />
    </FormsFormField>
  </FormsFormShell>
</template>
