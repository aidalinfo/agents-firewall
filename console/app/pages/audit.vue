<script setup lang="ts">
import type { AuditEntry, AuditVerify, Interface } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()

useHead({ title: () => `${t('nav.audit')} — agents-firewall` })

const entries = ref<AuditEntry[]>([])
const cursor = ref<string | null>(null)
const chain = ref<AuditVerify | null>(null)
const iface = ref<Interface | 'all'>('all')
const actor = ref<string>('all')
const actors = ref<string[]>([])
const loading = ref(false)

async function load(reset = true) {
  loading.value = true
  try {
    const page = await api.listAudit({
      interface: iface.value === 'all' ? undefined : iface.value,
      actor: actor.value === 'all' ? undefined : actor.value,
      cursor: reset ? undefined : cursor.value ?? undefined,
      limit: 50,
    })
    entries.value = reset ? page.items : [...entries.value, ...page.items]
    cursor.value = page.next_cursor
    if (reset && iface.value === 'all' && actor.value === 'all') actors.value = [...new Set(page.items.map(e => e.actor.name))]
  }
  finally {
    loading.value = false
  }
}

const exporting = ref(false)
const toast = useToast()

/** Fetches the export with the bearer token (never a token in a URL), then saves it as a file. */
async function exportAudit() {
  exporting.value = true
  try {
    const blob = await api.exportAudit()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-${new Date().toISOString().slice(0, 10)}.ndjson`
    a.rel = 'noopener'
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  catch (e) {
    toast.add({ title: t('audit.exportFailed'), description: e instanceof Error ? e.message : String(e), color: 'error' })
  }
  finally {
    exporting.value = false
  }
}

async function verify() {
  chain.value = await api.verifyAudit()
}

onMounted(() => Promise.all([load(), verify()]))
watch([iface, actor], () => load())

const ifaceItems = computed(() => [{ label: t('audit.allInterfaces'), value: 'all' }, ...(['ui', 'cli', 'mcp', 'api', 'system'] as const).map(v => ({ label: t(`audit.iface.${v}`), value: v }))])
const actorItems = computed(() => [{ label: t('audit.allAuthors'), value: 'all' }, ...actors.value.map(a => ({ label: a, value: a }))])
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.audit')"
      :subtitle="t('audit.subtitle')"
    >
      <template #actions>
        <UButton
          color="neutral"
          variant="outline"
          size="sm"
          icon="i-lucide-download"
          :loading="exporting"
          data-testid="audit-export"
          @click="exportAudit"
        >
          {{ t('audit.export') }}
        </UButton>
      </template>
    </ShellPageHeader>
    <div class="flex flex-col gap-4 p-4">
      <section class="afw-card overflow-x-auto">
        <div class="flex flex-wrap items-center gap-[10px] px-[14px] py-3">
          <USelect
            v-model="actor"
            :items="actorItems"
            size="sm"
            class="w-48"
            :aria-label="t('audit.col.author')"
          />
          <USelect
            v-model="iface"
            :items="ifaceItems"
            size="sm"
            class="w-44"
            :aria-label="t('audit.col.interface')"
          />
          <span class="flex-1" />
          <span
            v-if="chain"
            class="inline-flex items-center gap-1.5 text-xs font-semibold"
            :class="chain.ok ? 'text-ok' : 'text-ko'"
            data-testid="audit-chain"
          >
            <UIcon
              :name="chain.ok ? 'i-lucide-shield-check' : 'i-lucide-shield-alert'"
              class="size-[13px]"
            />{{ chain.ok ? t('audit.chainChecked', { n: chain.checked, at: fmt.hm(chain.anchor_exported_at) }) : t('audit.chainKo') }}
          </span>
          <UButton
            color="neutral"
            variant="outline"
            size="xs"
            icon="i-lucide-refresh-cw"
            @click="verify"
          >
            {{ t('audit.verify') }}
          </UButton>
        </div>
        <AuditTable :entries="entries" />
        <div
          v-if="cursor"
          class="flex justify-center p-3"
        >
          <UButton
            color="neutral"
            variant="ghost"
            :loading="loading"
            @click="load(false)"
          >
            {{ t('common.loadMore') }}
          </UButton>
        </div>
      </section>
    </div>
  </div>
</template>
