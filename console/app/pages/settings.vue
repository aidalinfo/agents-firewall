<script setup lang="ts">
import type { AlertChannel, ApiToken } from '~/api/types'

/** Alert channels and API tokens (not part of policy sessions: written directly, audited by the API). */
const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const problem = useProblem()
const dir = useDirectory()

useHead({ title: () => `${t('nav.settings')} — agents-firewall` })

const channels = ref<AlertChannel[]>([])
const tokens = ref<ApiToken[]>([])
const channelOpen = ref(false)
const editingChannel = ref<AlertChannel | null>(null)
const tokenOpen = ref(false)

async function load() {
  try {
    const [c, tk] = await Promise.all([api.alertChannels.list(), api.listTokens(), dir.ensure()])
    channels.value = c
    tokens.value = tk
  }
  catch (e) {
    problem.notify(e)
  }
}
onMounted(load)

function newChannel() {
  editingChannel.value = null
  channelOpen.value = true
}
function editChannel(c: AlertChannel) {
  editingChannel.value = c
  channelOpen.value = true
}
async function removeChannel(c: AlertChannel) {
  try {
    await api.alertChannels.remove(c.id)
    await load()
  }
  catch (e) {
    problem.notify(e)
  }
}
async function revoke(tk: ApiToken) {
  try {
    await api.revokeToken(tk.id)
    await load()
  }
  catch (e) {
    problem.notify(e)
  }
}
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.settings')"
      :subtitle="t('settings.subtitle')"
    />
    <div class="flex flex-col gap-4 p-4">
      <section
        aria-labelledby="channels-title"
        class="afw-card flex flex-col"
      >
        <div class="flex items-center gap-2 border-b border-line px-[14px] py-3">
          <h2
            id="channels-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('alerts.channelsTitle') }}
          </h2>
          <span class="text-xs text-text3">{{ t('settings.channelsSub') }}</span>
          <span class="flex-1" />
          <UButton
            size="sm"
            icon="i-lucide-plus"
            color="neutral"
            variant="outline"
            data-testid="channel-create"
            @click="newChannel"
          >
            {{ t('channels.form.create') }}
          </UButton>
        </div>
        <div
          v-for="c in channels"
          :key="c.id"
          class="flex flex-wrap items-center gap-3 border-b border-line px-[14px] py-2 text-[12.5px]"
          :data-testid="`channel-${c.name}`"
        >
          <span
            class="size-2 rounded-full"
            :class="c.enabled ? 'bg-ok' : 'bg-text3'"
          />
          <strong>{{ c.name }}</strong>
          <span class="text-text3">{{ t(`alerts.channelKind.${c.kind}`) }} · ≥ {{ t(`severity.${c.min_severity}`) }}</span>
          <span class="min-w-0 flex-1 truncate font-mono text-[11.5px] text-text2">{{ c.url }}</span>
          <UButton
            size="xs"
            color="neutral"
            variant="ghost"
            icon="i-lucide-pencil"
            :aria-label="t('common.edit')"
            @click="editChannel(c)"
          />
          <UButton
            size="xs"
            color="error"
            variant="ghost"
            icon="i-lucide-trash-2"
            :aria-label="t('common.delete')"
            @click="removeChannel(c)"
          />
        </div>
        <p
          v-if="!channels.length"
          class="m-0 px-[14px] py-4 text-center text-text3"
        >
          {{ t('settings.noChannel') }}
        </p>
      </section>

      <section
        aria-labelledby="tokens-title"
        class="afw-card flex flex-col"
      >
        <div class="flex items-center gap-2 border-b border-line px-[14px] py-3">
          <h2
            id="tokens-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('tokens.title') }}
          </h2>
          <span class="text-xs text-text3">{{ t('tokens.subtitle') }}</span>
          <span class="flex-1" />
          <UButton
            size="sm"
            icon="i-lucide-key-round"
            color="neutral"
            variant="outline"
            data-testid="token-create"
            @click="tokenOpen = true"
          >
            {{ t('tokens.form.create') }}
          </UButton>
        </div>
        <div class="overflow-x-auto">
          <div class="min-w-[680px]">
            <div class="afw-th grid grid-cols-[minmax(150px,1fr)_110px_120px_110px_110px_110px_40px] gap-[10px] border-b border-line px-[14px] py-1.5">
              <span>{{ t('form.name') }}</span><span>{{ t('tokens.role') }}</span><span>{{ t('tokens.agent') }}</span><span>{{ t('tokens.created') }}</span><span>{{ t('tokens.lastUsed') }}</span><span>{{ t('tokens.expires') }}</span><span />
            </div>
            <div
              v-for="tk in tokens"
              :key="tk.id"
              class="grid grid-cols-[minmax(150px,1fr)_110px_120px_110px_110px_110px_40px] items-center gap-[10px] border-b border-line px-[14px] py-2 text-xs"
              :data-testid="`token-${tk.name}`"
            >
              <span class="flex flex-col leading-[1.3]"><strong class="truncate">{{ tk.name }}</strong><span class="text-[11px] text-text3">{{ tk.created_by.name }}</span></span>
              <span>{{ t(`role.${tk.role}`) }}</span>
              <span class="truncate font-mono text-[11.5px]">{{ dir.agentName(tk.agent_id) ?? '—' }}</span>
              <span class="text-text2">{{ fmt.date(tk.created_at) }}</span>
              <span class="text-text2">{{ fmt.rel(tk.last_used_at) }}</span>
              <span class="text-text2">{{ tk.expires_at ? fmt.date(tk.expires_at) : '—' }}</span>
              <UButton
                size="xs"
                color="error"
                variant="ghost"
                icon="i-lucide-trash-2"
                :aria-label="t('tokens.revoke')"
                @click="revoke(tk)"
              />
            </div>
          </div>
        </div>
      </section>
    </div>
    <FormsAlertChannelForm
      v-model:open="channelOpen"
      :channel="editingChannel"
      @saved="load"
    />
    <FormsTokenForm
      v-model:open="tokenOpen"
      @saved="load"
    />
  </div>
</template>
