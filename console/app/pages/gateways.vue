<script setup lang="ts">
import type { Gateway, GatewayCommandKind, Install, RegistrationToken } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const copy = useCopy()
const { gateways, refreshShell } = useShell()

useHead({ title: () => `${t('nav.gateways')} — agents-firewall` })

const installs = ref<Install[]>([])
const token = ref<RegistrationToken | null>(null)
const tokenOpen = ref(false)

onMounted(async () => {
  installs.value = await api.listInstalls()
  await gateways.refresh()
})

const history = computed(() => installs.value.flatMap(i => i.results.map(r => ({ ...r, key: `${i.id}-${r.gateway_id}` }))).slice(0, 8))

function look(g: Gateway) {
  if (g.status === 'online') return { dot: 'bg-ok', st: 'bg-ok-bg text-ok', border: 'border-line' }
  if (g.status === 'degraded') return { dot: 'bg-warn', st: 'bg-warn-bg text-warn', border: 'border-warn' }
  return { dot: 'bg-ko', st: 'bg-ko-bg text-ko', border: 'border-ko' }
}

function link(g: Gateway) {
  return g.link === 'mtls' ? t('gateways.linkOk', { when: fmt.rel(g.last_seen_at) }) : t('gateways.linkLost', { at: fmt.hm(g.last_seen_at) })
}

async function command(g: Gateway, c: GatewayCommandKind) {
  await api.sendGatewayCommand(g.id, c)
  toast.add({ title: t(`gateways.cmdSent.${c}`, { gw: g.name }), icon: 'i-lucide-send' })
}

async function register() {
  token.value = await api.createRegistrationToken()
  tokenOpen.value = true
}

onMounted(() => void refreshShell())
</script>

<template>
  <div class="flex flex-1 flex-col">
    <ShellPageHeader
      :title="t('nav.gateways')"
      :subtitle="t('gateways.subtitle')"
    >
      <template #actions>
        <UButton
          class="bg-text font-semibold text-bg hover:bg-text/90"
          data-testid="register-gateway"
          @click="register"
        >
          {{ t('gateways.register') }}
        </UButton>
      </template>
    </ShellPageHeader>

    <div class="flex flex-col gap-4 p-4">
      <div class="grid grid-cols-[repeat(auto-fit,minmax(min(340px,100%),1fr))] gap-3">
        <article
          v-for="g in gateways.data.value"
          :key="g.id"
          class="flex flex-col rounded-[10px] border bg-panel"
          :class="look(g).border"
          :data-testid="`gateway-${g.name}`"
        >
          <div class="flex items-start gap-[10px] border-b border-line px-[14px] py-3">
            <span
              class="mt-[5px] size-[10px] flex-none rounded-full"
              :class="look(g).dot"
            />
            <div class="flex min-w-0 flex-1 flex-col gap-px">
              <h2 class="m-0 font-mono text-[14.5px] font-semibold">
                {{ g.name }}
              </h2>
              <span class="text-xs text-text2">{{ g.environment }}</span>
            </div>
            <span
              class="rounded-full px-2 py-px text-[11.5px] font-bold"
              :class="look(g).st"
            >{{ g.status_detail ? t(`gateways.detail.${g.status_detail}`) : t(`gateways.status.${g.status}`) }}</span>
          </div>
          <div
            v-if="g.status_detail"
            class="border-b border-line bg-warn-bg px-[14px] py-2 text-xs text-text"
          >
            {{ t(`gateways.warn.${g.status_detail}`, { since: fmt.rel(g.last_seen_at), n: g.revision }) }}
          </div>
          <dl class="m-0 grid grid-cols-[136px_minmax(0,1fr)] gap-x-[10px] gap-y-1.5 px-[14px] py-3 text-[12.5px]">
            <dt class="text-text3">
              {{ t('gateways.policy') }}
            </dt><dd class="m-0 font-semibold">
              {{ t('gateways.revAt', { n: g.revision, at: fmt.dateTime(g.revision_installed_at) }) }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.version') }}
            </dt><dd class="m-0 font-mono text-xs">
              {{ g.version }}<template v-if="g.update_available">
                · {{ t('gateways.available', { v: g.update_available }) }}
              </template>
            </dd>
            <dt class="text-text3">
              {{ t('gateways.link') }}
            </dt><dd
              class="m-0"
              :class="g.link === 'mtls' ? '' : 'text-warn'"
            >
              {{ link(g) }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.agents') }}
            </dt><dd class="m-0 font-mono text-xs">
              {{ g.agents.join(', ') }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.rate') }}
            </dt><dd class="m-0">
              {{ t('gateways.rateValue', { n: g.stats.flows_per_min, v: fmt.bytes(g.stats.bytes_out_per_min) }) }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.latency') }}
            </dt><dd class="m-0">
              p50 {{ g.stats.latency_p50_ms }} ms · p95 {{ g.stats.latency_p95_ms }} ms
            </dd>
            <dt class="text-text3">
              {{ t('gateways.tls') }}
            </dt><dd class="m-0">
              {{ g.tls }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.isolation') }}
            </dt><dd class="m-0">
              {{ g.isolation }}
            </dd>
          </dl>
          <div class="mt-auto flex flex-wrap gap-1.5 border-t border-line px-[14px] py-[10px]">
            <button
              type="button"
              class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
              @click="command(g, 'reinstall')"
            >
              {{ t('gateways.reinstall') }}
            </button>
            <button
              type="button"
              class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
              @click="command(g, 'self_test')"
            >
              {{ t('gateways.selfTest') }}
            </button>
            <NuxtLink
              :to="{ path: '/', query: { q: g.agents.map(a => `agent:${a}`)[0] ?? '' } }"
              class="flex h-7 items-center rounded-md border border-line2 px-[10px] text-xs font-medium no-underline"
              style="color: var(--text)"
            >
              {{ t('gateways.logs') }}
            </NuxtLink>
          </div>
        </article>
      </div>

      <div class="flex flex-wrap items-start gap-4">
        <section
          aria-labelledby="hist-title"
          class="afw-card min-w-0 flex-[999_1_560px] overflow-x-auto"
        >
          <div class="flex items-baseline gap-[10px] px-[14px] pt-3 pb-2">
            <h2
              id="hist-title"
              class="m-0 text-sm font-[650]"
            >
              {{ t('gateways.lastInstalls') }}
            </h2>
            <NuxtLink
              to="/revisions"
              class="text-xs"
            >
              {{ t('nav.revisions') }}
            </NuxtLink>
          </div>
          <div class="min-w-[560px]">
            <div class="afw-th grid grid-cols-[110px_70px_130px_110px_minmax(140px,1fr)] gap-[10px] border-y border-line px-[14px] py-1.5">
              <span>{{ t('gateways.col.date') }}</span><span>{{ t('gateways.col.rev') }}</span><span>{{ t('gateways.col.gateway') }}</span><span>{{ t('gateways.col.result') }}</span><span>{{ t('gateways.col.by') }}</span>
            </div>
            <div
              v-for="h in history"
              :key="h.key"
              class="grid grid-cols-[110px_70px_130px_110px_minmax(140px,1fr)] items-center gap-[10px] border-b border-line px-[14px] py-[7px] text-xs"
            >
              <span class="font-mono text-[11.5px] text-text2">{{ fmt.dateTime(h.at) }}</span>
              <span class="font-mono font-semibold">{{ h.revision }}</span>
              <span class="font-mono text-[11.5px]">{{ h.gateway_name }}</span>
              <span
                class="font-semibold"
                :class="h.ok ? 'text-ok' : 'text-warn'"
              >{{ h.ok ? t('gateways.success') : h.error }}</span>
              <span class="text-text2">{{ h.by }}</span>
            </div>
          </div>
        </section>

        <section
          aria-labelledby="enroll-title"
          class="afw-card flex min-w-0 flex-[1_1_380px] flex-col gap-[10px] px-[14px] py-3"
        >
          <h2
            id="enroll-title"
            class="m-0 text-sm font-[650]"
          >
            {{ t('gateways.add') }}
          </h2>
          <div class="flex flex-col gap-1">
            <span class="text-xs font-semibold">{{ t('gateways.addGateway') }}</span>
            <code class="rounded-md border border-line bg-code px-[10px] py-2 font-mono text-[11.5px] break-all">afw gateway register --token afw_rt_••••••••3f9a</code>
          </div>
          <div class="flex flex-col gap-1">
            <span class="text-xs font-semibold">{{ t('gateways.addAgent') }}</span>
            <code class="rounded-md border border-line bg-code px-[10px] py-2 font-mono text-[11.5px] break-all">afw enroll hermes-paie --zone nouveaux-bots</code>
          </div>
          <span class="text-[11.5px] text-text3">{{ t('gateways.addNote') }}</span>
        </section>
      </div>
    </div>

    <UModal
      v-model:open="tokenOpen"
      :title="t('gateways.tokenTitle')"
      :description="t('gateways.tokenText', { at: fmt.hm(token?.expires_at) })"
    >
      <template #body>
        <div class="flex flex-col gap-2">
          <code
            class="rounded-md border border-line bg-code px-[10px] py-2 font-mono text-[12px] break-all"
            data-testid="registration-command"
          >{{ token?.command }}</code>
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-copy"
            class="self-end"
            @click="token && copy(token.command)"
          >
            {{ t('common.copy') }}
          </UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
