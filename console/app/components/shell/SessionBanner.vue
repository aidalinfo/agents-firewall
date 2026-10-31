<script setup lang="ts">
import type { Approval } from '~/api/types'

/**
 * Banner of the caller's session when a publish is waiting for a human approval (HTTP 202,
 * EF-52). The decision is taken by another administrator (never the requester).
 */
const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const { session, approval, refresh } = usePolicySession()
const current = ref<Approval | null>(null)

const id = computed(() => approval.value?.id ?? session.value?.approval_id ?? null)
watch(id, async (v) => {
  current.value = approval.value?.id === v ? approval.value : null
  if (!v) return
  try {
    current.value = (await api.listApprovals()).find(a => a.id === v) ?? current.value
  }
  catch {
    // keep what the publish answer gave
  }
}, { immediate: true })

async function check() {
  await refresh()
  if (id.value) current.value = (await api.listApprovals()).find(a => a.id === id.value) ?? current.value
}
</script>

<template>
  <div
    v-if="id && current"
    role="status"
    class="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2 text-[12.5px]"
    :class="current.status === 'rejected' ? 'bg-ko-bg' : current.status === 'approved' ? 'bg-ok-bg' : 'bg-warn-bg'"
    data-testid="approval-banner"
  >
    <UIcon
      name="i-lucide-hourglass"
      class="size-4"
      :class="current.status === 'rejected' ? 'text-ko' : current.status === 'approved' ? 'text-ok' : 'text-warn'"
    />
    <strong>{{ t(`approval.status.${current.status}`) }}</strong>
    <span class="text-text2">{{ t('approval.detail', { who: current.requested_by.name, when: fmt.rel(current.requested_at), summary: current.summary }) }}</span>
    <span
      v-if="current.decided_by"
      class="text-text2"
    >{{ t('approval.decided', { who: current.decided_by.name }) }}<template v-if="current.comment"> · « {{ current.comment }} »</template></span>
    <span class="flex-1" />
    <UButton
      size="xs"
      color="neutral"
      variant="outline"
      icon="i-lucide-refresh-cw"
      @click="check"
    >
      {{ t('approval.check') }}
    </UButton>
  </div>
</template>
