<script setup lang="ts">
import type { Gateway, GatewayCommand, Install, RegistrationToken } from '~/api/types'

const { t } = useI18n()
const api = useApi()
const fmt = useFmt()
const toast = useToast()
const copy = useCopy()
const problem = useProblem()
const dir = useDirectory()
const { gateways, refreshShell } = useShell()

useHead({ title: () => `${t('nav.gateways')} — agents-firewall` })

const installs = ref<Install[]>([])
const token = ref<RegistrationToken | null>(null)
const tokenOpen = ref(false)
const tokenName = ref('')
const removing = ref<Gateway | null>(null)

async function load() {
  try {
    installs.value = (await api.listInstalls({ limit: 8 })).items
    await Promise.all([gateways.refresh(), dir.ensure()])
  }
  catch (e) {
    problem.notify(e)
  }
}
onMounted(load)

function look(g: Gateway) {
  if (g.status === 'online') return { dot: 'bg-ok', st: 'bg-ok-bg text-ok', border: 'border-line' }
  if (g.status === 'pending') return { dot: 'bg-warn', st: 'bg-warn-bg text-warn', border: 'border-warn' }
  return { dot: 'bg-ko', st: 'bg-ko-bg text-ko', border: 'border-ko' }
}

/** The gateway runs an older revision than the one requested (installation not acknowledged yet). */
const behind = (g: Gateway) => g.desired_revision != null && g.active_revision !== g.desired_revision
const agentsOf = (g: Gateway) => dir.data.value.agents.filter(a => a.gateway_id === g.id).map(a => a.name)
const uptime = (secs: number) => fmt.duration(secs * 1000)

async function command(g: Gateway, c: GatewayCommand) {
  try {
    await api.sendGatewayCommand(g.id, c)
    toast.add({ title: t(`gateways.cmdSent.${c.type}`, { gw: g.name }), icon: 'i-lucide-send' })
  }
  catch (e) {
    problem.notify(e)
  }
}

async function register() {
  try {
    token.value = await api.createRegistrationToken(tokenName.value.trim() || null)
    tokenOpen.value = true
  }
  catch (e) {
    problem.notify(e)
  }
}

/** Command the operator runs on the agents host (the token is only valid 15 minutes). */
const registerCommand = computed(() => (token.value ? `AFW_REGISTRATION_TOKEN='${token.value.token.replace(/'/g, `'\\''`)}' docker compose -f gateway.yml up -d` : ''))

async function remove() {
  const g = removing.value
  if (!g) return
  try {
    await api.deleteGateway(g.id)
    removing.value = null
    await Promise.all([load(), refreshShell()])
  }
  catch (e) {
    problem.notify(e)
  }
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
              <span class="font-mono text-xs text-text2">{{ g.hostname }}</span>
            </div>
            <span
              class="rounded-full px-2 py-px text-[11.5px] font-bold"
              :class="look(g).st"
            >{{ t(`gateways.status.${g.status}`) }}</span>
          </div>
          <div
            v-if="g.status !== 'online' || behind(g)"
            class="border-b border-line bg-warn-bg px-[14px] py-2 text-xs text-text"
          >
            {{ g.status === 'offline' ? t('gateways.warn.offline', { since: fmt.rel(g.last_seen_at), n: g.active_revision ?? '—' }) : g.status === 'pending' ? t('gateways.warn.pending') : t('gateways.warn.behind', { n: g.active_revision ?? '—', d: g.desired_revision }) }}
          </div>
          <dl class="m-0 grid grid-cols-[136px_minmax(0,1fr)] gap-x-[10px] gap-y-1.5 px-[14px] py-3 text-[12.5px]">
            <dt class="text-text3">
              {{ t('gateways.policy') }}
            </dt><dd class="m-0 font-semibold">
              {{ g.active_revision != null ? t('gateways.rev', { n: g.active_revision }) : '—' }}<template v-if="behind(g)">
                · {{ t('gateways.desired', { n: g.desired_revision }) }}
              </template>
            </dd>
            <dt class="text-text3">
              {{ t('gateways.version') }}
            </dt><dd class="m-0 font-mono text-xs">
              {{ g.version ?? '—' }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.link') }}
            </dt><dd
              class="m-0"
              :class="g.status === 'online' ? '' : 'text-warn'"
            >
              {{ g.last_seen_at ? t('gateways.seen', { when: fmt.rel(g.last_seen_at) }) : t('gateways.neverSeen') }}
            </dd>
            <dt class="text-text3">
              {{ t('gateways.agents') }}
            </dt><dd class="m-0 font-mono text-xs">
              {{ agentsOf(g).join(', ') || '—' }}
            </dd>
            <template v-if="g.stats">
              <dt class="text-text3">
                {{ t('gateways.flows') }}
              </dt><dd class="m-0">
                {{ t('gateways.flowsValue', { n: fmt.num(g.stats.flows_total), d: fmt.num(g.stats.denied_total), a: g.stats.active_flows }) }}
              </dd>
              <dt class="text-text3">
                {{ t('gateways.volume') }}
              </dt><dd class="m-0">
                ↑ {{ fmt.bytes(g.stats.bytes_out) }} · ↓ {{ fmt.bytes(g.stats.bytes_in) }}
              </dd>
              <dt class="text-text3">
                {{ t('gateways.buffer') }}
              </dt><dd
                class="m-0"
                :class="g.stats.events_dropped ? 'font-semibold text-ko' : ''"
              >
                {{ t('gateways.bufferValue', { q: g.stats.events_queued, d: g.stats.events_dropped }) }}
              </dd>
              <dt class="text-text3">
                {{ t('gateways.latency') }}
              </dt><dd class="m-0">
                p50 {{ g.stats.p50_ms }} ms · p95 {{ g.stats.p95_ms }} ms
              </dd>
              <dt class="text-text3">
                {{ t('gateways.uptime') }}
              </dt><dd class="m-0">
                {{ uptime(g.stats.uptime_secs) }}
              </dd>
            </template>
            <dt class="text-text3">
              {{ t('gateways.ca') }}
            </dt><dd class="m-0 truncate font-mono text-xs">
              {{ g.ca_fingerprint ?? '—' }}
            </dd>
          </dl>
          <div class="mt-auto flex flex-wrap gap-1.5 border-t border-line px-[14px] py-[10px]">
            <button
              type="button"
              class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
              @click="command(g, { type: 'reinstall' })"
            >
              {{ t('gateways.reinstall') }}
            </button>
            <button
              type="button"
              class="h-7 rounded-md border border-line2 bg-transparent px-[10px] text-xs font-medium"
              @click="command(g, { type: 'self_test' })"
            >
              {{ t('gateways.selfTest') }}
            </button>
            <span class="flex-1" />
            <button
              type="button"
              class="h-7 rounded-md border-0 bg-transparent px-[10px] text-xs font-medium text-ko"
              :data-testid="`gateway-remove-${g.name}`"
              @click="removing = g"
            >
              {{ t('gateways.remove') }}
            </button>
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
              v-for="h in installs"
              :key="h.id"
              class="grid grid-cols-[110px_70px_130px_110px_minmax(140px,1fr)] items-center gap-[10px] border-b border-line px-[14px] py-[7px] text-xs"
            >
              <span class="font-mono text-[11.5px] text-text2">{{ fmt.dateTime(h.requested_at) }}</span>
              <span class="font-mono font-semibold">{{ h.revision }}</span>
              <span class="font-mono text-[11.5px]">{{ dir.gatewayName(h.gateway_id) ?? h.gateway_id.slice(0, 8) }}</span>
              <span
                class="font-semibold"
                :class="h.state === 'installed' ? 'text-ok' : h.state === 'failed' ? 'text-ko' : 'text-warn'"
              >{{ h.state === 'failed' ? h.error ?? t('gateways.state.failed') : t(`gateways.state.${h.state}`) }}</span>
              <span class="text-text2">{{ h.requested_by.name }}</span>
            </div>
            <div
              v-if="!installs.length"
              class="px-[14px] py-3 text-text3"
            >
              {{ t('revisions.notInstalled') }}
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
            <label
              for="gw-name"
              class="text-xs font-semibold"
            >{{ t('gateways.addGateway') }}</label>
            <div class="flex gap-2">
              <UInput
                id="gw-name"
                v-model="tokenName"
                size="sm"
                :placeholder="t('gateways.namePh')"
                class="flex-1"
              />
              <UButton
                size="sm"
                color="neutral"
                variant="outline"
                @click="register"
              >
                {{ t('gateways.token') }}
              </UButton>
            </div>
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
          >{{ registerCommand }}</code>
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-copy"
            class="self-end"
            @click="token && copy(registerCommand)"
          >
            {{ t('common.copy') }}
          </UButton>
        </div>
      </template>
    </UModal>
    <UModal
      :open="!!removing"
      :title="t('gateways.removeTitle', { gw: removing?.name ?? '' })"
      :description="t('gateways.removeText')"
      @update:open="(v: boolean) => { if (!v) removing = null }"
    >
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="outline"
            @click="removing = null"
          >
            {{ t('common.cancel') }}
          </UButton>
          <UButton
            color="error"
            data-testid="gateway-remove-confirm"
            @click="remove"
          >
            {{ t('gateways.remove') }}
          </UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
