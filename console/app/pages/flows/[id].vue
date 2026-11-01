<script setup lang="ts">
import type { FlowDetail } from '~/api/types'
import { shortFlowId } from '~/utils/format'

const { t } = useI18n()
const api = useApi()
const route = useRoute()
const id = computed(() => String(route.params.id))
const { refreshShell } = useShell()

const detail = ref<FlowDetail | null>(null)
const error = ref<string | null>(null)
const loading = ref(true)

watch(id, async (v) => {
  loading.value = true
  error.value = null
  try {
    detail.value = await api.getFlow(v)
  }
  catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
  finally {
    loading.value = false
  }
}, { immediate: true })

useHead({ title: () => `${shortFlowId(id.value)} — agents-firewall` })
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :prefix="t('journal.prefix')"
      :title="t('flow.pageTitle', { id: shortFlowId(id) })"
    >
      <NuxtLink
        :to="{ path: '/', query: { flow: id } }"
        class="text-xs"
      >
        ← {{ t('flow.backToJournal') }}
      </NuxtLink>
    </ShellPageHeader>
    <div class="mx-auto flex w-full max-w-[960px] flex-col gap-3 px-4 py-[14px]">
      <UAlert
        v-if="error"
        color="error"
        variant="subtle"
        :title="t('flow.notFound')"
        :description="error"
      />
      <FlowDetailPanel
        v-else
        :detail="detail"
        :loading="loading"
        standalone
        @added="refreshShell"
      />
    </div>
  </div>
</template>
