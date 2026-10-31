<script setup lang="ts">
import type { Alert, AlertChannel } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const problem = useProblem()
const { refreshShell } = useShell()

useHead({ title: () => `${t('nav.alerts')} — agents-firewall` })

const filter = ref<'open' | 'all' | 'resolved'>('open')
const channels = ref<AlertChannel[]>([])
const alerts = ref<Alert[]>([])

async function load() {
  try {
    const acknowledged = filter.value === 'all' ? undefined : filter.value === 'resolved'
    alerts.value = (await api.listAlerts({ acknowledged })).items
  }
  catch (e) {
    problem.notify(e)
  }
}
watch(filter, () => void load())
onMounted(async () => {
  await load()
  channels.value = await api.alertChannels.list().catch(() => [])
})

async function changed() {
  await Promise.all([load(), refreshShell()])
}

const order = { critical: 0, warning: 1, info: 2 } as const
const shown = computed(() => [...alerts.value].sort((a, b) => order[a.event.severity] - order[b.event.severity] || b.event.at.localeCompare(a.event.at)))
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.alerts')"
      :subtitle="t('alerts.subtitle')"
    />
    <div class="flex flex-wrap items-start gap-4 p-4">
      <section class="afw-card min-w-0 flex-[999_1_560px]">
        <div class="flex flex-wrap items-center gap-2 border-b border-line px-[14px] py-3">
          <UTabs
            v-model="filter"
            :items="[{ label: t('alerts.filter.open'), value: 'open' }, { label: t('alerts.filter.resolved'), value: 'resolved' }, { label: t('alerts.filter.all'), value: 'all' }]"
            :content="false"
            size="xs"
          />
        </div>
        <AlertsAlertList
          :alerts="shown"
          @changed="changed"
        />
        <p
          v-if="!shown.length"
          class="m-0 p-6 text-center text-text3"
        >
          {{ t('alerts.none') }}
        </p>
      </section>
      <section class="afw-card flex min-w-0 flex-[1_1_320px] flex-col gap-3 px-[14px] py-3">
        <div class="flex items-center justify-between gap-2">
          <h2 class="m-0 text-sm font-[650]">
            {{ t('alerts.channelsTitle') }}
          </h2>
          <NuxtLink
            to="/settings"
            class="text-xs"
          >{{ t('alerts.manageChannels') }}</NuxtLink>
        </div>
        <ul class="m-0 flex list-none flex-col gap-2 p-0">
          <li
            v-for="c in channels"
            :key="c.id"
            class="flex items-center gap-2 text-[12.5px]"
          >
            <span
              class="size-2 rounded-full"
              :class="c.enabled ? 'bg-ok' : 'bg-text3'"
            />
            <strong>{{ c.name }}</strong><span class="text-text3">{{ t(`alerts.channelKind.${c.kind}`) }} · ≥ {{ t(`severity.${c.min_severity}`) }}</span>
          </li>
        </ul>
        <p class="m-0 text-[11.5px] text-text3">
          {{ t('alerts.kindsNote') }}
        </p>
      </section>
    </div>
  </div>
</template>
