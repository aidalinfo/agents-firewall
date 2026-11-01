<script setup lang="ts">
import type { InspectionRule } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const problem = useProblem()
const dir = useDirectory()
const { session, ensureOpen, refresh: refreshSession } = usePolicySession()

useHead({ title: () => `${t('nav.inspection')} — agents-firewall` })

const rules = ref<InspectionRule[]>([])
const formOpen = ref(false)
const editing = ref<InspectionRule | null>(null)

async function load() {
  try {
    await dir.ensure()
    rules.value = (await api.inspectionRules.list()).sort((a, b) => a.position - b.position)
  }
  catch (e) {
    problem.notify(e)
  }
}
onMounted(load)
watch(() => session.value?.id, () => void load())

function create() {
  editing.value = null
  formOpen.value = true
}
function edit(r: InspectionRule) {
  editing.value = r
  formOpen.value = true
}
async function remove(r: InspectionRule) {
  try {
    const s = await ensureOpen(t('rules.defaultSessionName'))
    await api.inspectionRules.remove(s.id, r.id)
    await refreshSession()
    await load()
  }
  catch (e) {
    problem.notify(e)
  }
}
const names = (ids: string[], name: (id: string) => string | null, empty: string) => ids.map(id => name(id) ?? id.slice(0, 8)).join(', ') || empty
const inSession = (r: InspectionRule) => !!session.value?.locks.some(l => l.id === r.id)
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.inspection')"
      :subtitle="t('inspection.subtitle')"
    >
      <template #actions>
        <UButton
          class="bg-text font-semibold text-bg hover:bg-text/90"
          icon="i-lucide-plus"
          data-testid="inspection-create"
          @click="create"
        >
          {{ t('inspection.new') }}
        </UButton>
      </template>
    </ShellPageHeader>
    <div class="p-4">
      <div class="afw-card overflow-x-auto">
        <div class="min-w-[760px]">
          <div class="afw-th grid grid-cols-[42px_minmax(180px,1.3fr)_minmax(140px,1fr)_minmax(160px,1fr)_110px_72px] gap-[10px] border-b border-line px-[14px] py-2">
            <span>{{ t('rules.col.n') }}</span><span>{{ t('rules.col.name') }}</span><span>{{ t('inspection.zones') }}</span><span>{{ t('rules.col.destination') }}</span><span>{{ t('rules.col.action') }}</span><span />
          </div>
          <div
            v-for="r in rules"
            :key="r.id"
            class="grid grid-cols-[42px_minmax(180px,1.3fr)_minmax(140px,1fr)_minmax(160px,1fr)_110px_72px] items-center gap-[10px] border-b border-line px-[14px] py-2 text-[12.5px]"
            :class="inSession(r) ? 'bg-pri-bg' : ''"
            :data-testid="`inspection-${r.position}`"
          >
            <span class="font-mono text-xs font-semibold">{{ r.position }}</span>
            <span class="truncate font-semibold">{{ r.name }}</span>
            <span class="truncate text-xs">{{ names(r.zones, dir.zoneName, t('rules.all')) }}</span>
            <span class="truncate font-mono text-[11.5px]">{{ names(r.destinations, dir.objectName, t('rules.anyDest')) }}</span>
            <span><span
              class="rounded-full px-2 py-0.5 text-[11.5px] font-[650]"
              :class="r.action === 'bypass' ? 'bg-warn-bg text-warn' : 'bg-ok-bg text-ok'"
            >{{ t(`inspection.action.${r.action}`) }}</span></span>
            <span class="flex justify-end gap-1">
              <UButton
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-pencil"
                :aria-label="t('common.edit')"
                @click="edit(r)"
              />
              <UButton
                size="xs"
                color="error"
                variant="ghost"
                icon="i-lucide-trash-2"
                :aria-label="t('common.delete')"
                @click="remove(r)"
              />
            </span>
          </div>
          <div class="grid grid-cols-[42px_minmax(180px,1.3fr)_minmax(140px,1fr)_minmax(160px,1fr)_110px_72px] items-center gap-[10px] px-[14px] py-2 text-[12.5px] text-text2">
            <span class="font-mono text-xs">—</span>
            <span class="font-semibold">{{ t('inspection.default') }}</span>
            <span class="text-xs">{{ t('rules.all') }}</span>
            <span class="font-mono text-[11.5px]">{{ t('rules.anyDest') }}</span>
            <span><span class="rounded-full bg-ok-bg px-2 py-0.5 text-[11.5px] font-[650] text-ok">{{ t('inspection.action.inspect') }}</span></span>
            <span />
          </div>
        </div>
      </div>
    </div>
    <FormsInspectionRuleForm
      v-model:open="formOpen"
      :rule="editing"
      @saved="load"
    />
  </div>
</template>
