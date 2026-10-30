<script setup lang="ts">
import { NAV, isActive } from '~/utils/nav'

const { t, locale } = useI18n()
const switchLocale = useSwitchLocale()
const route = useRoute()
const { me, logout } = useAuth()
const { changeCount } = usePolicySession()
const { gateways, openCritical, openAlerts } = useShell()

const initials = computed(() => (me.value?.name ?? '?').split(/\s+/).map(p => p[0]).join('').slice(0, 2).toUpperCase())

function badge(key: string): { text: string, tone: 'ko' | 'warn' | 'neutral' } | null {
  if (key === 'internal' && openCritical.value) return { text: String(openCritical.value), tone: 'ko' }
  if (key === 'alerts' && openAlerts.value) return { text: String(openAlerts.value), tone: 'neutral' }
  if (key === 'rules' && changeCount.value) return { text: `+${changeCount.value}`, tone: 'warn' }
  return null
}

const userMenu = computed(() => [
  [
    {
      label: locale.value === 'fr' ? 'English' : 'Français',
      icon: 'i-lucide-languages',
      onSelect: () => switchLocale(locale.value === 'fr' ? 'en' : 'fr'),
    },
    { label: t('nav.logout'), icon: 'i-lucide-log-out', onSelect: () => logout() },
  ],
])
</script>

<template>
  <nav
    :aria-label="t('nav.aria')"
    class="flex h-full flex-col gap-4 border-r border-line bg-panel px-[10px] py-3"
  >
    <NuxtLink
      to="/"
      class="afw-ghost flex items-center gap-[10px] rounded-lg px-2 py-1.5 text-left no-underline"
      style="color: var(--text)"
    >
      <span class="flex size-[26px] flex-none items-center justify-center rounded-[7px] bg-pri text-pri-fg">
        <UIcon
          name="i-lucide-shield-check"
          class="size-[15px]"
        />
      </span>
      <span class="flex min-w-0 flex-1 flex-col leading-[1.2]">
        <strong class="text-[13.5px] font-[650]">agents-firewall</strong>
        <span class="font-mono text-[11px] text-text3">{{ me?.tenant ?? '—' }}</span>
      </span>
      <UIcon
        name="i-lucide-chevrons-up-down"
        class="size-3 text-text3"
      />
    </NuxtLink>

    <div
      v-for="group in NAV"
      :key="group.key"
      class="flex flex-col gap-px"
    >
      <span class="px-[10px] pb-1 font-mono text-[10.5px] text-text3">{{ t(`nav.group.${group.key}`) }}</span>
      <NuxtLink
        v-for="item in group.items"
        :key="item.key"
        :to="item.to"
        class="afw-nav flex items-center gap-[10px] rounded-md px-[10px] py-1.5 no-underline"
        :class="isActive(item, route.path) ? 'bg-sub font-semibold' : 'font-medium'"
        :style="{ color: isActive(item, route.path) ? 'var(--text)' : 'var(--text2)' }"
        :aria-current="isActive(item, route.path) ? 'page' : undefined"
        :data-testid="`nav-${item.key}`"
      >
        <UIcon
          :name="item.icon"
          class="size-[15px]"
          :class="isActive(item, route.path) ? 'text-pri' : ''"
        />
        <span class="flex-1">{{ t(`nav.${item.key}`) }}</span>
        <span
          v-if="item.key === 'gateways'"
          class="flex gap-[3px]"
          :aria-label="t('nav.gatewaysState', { online: gateways.data.value.filter(g => g.status === 'online').length, degraded: gateways.data.value.filter(g => g.status !== 'online').length })"
        >
          <span
            v-for="g in gateways.data.value"
            :key="g.id"
            class="size-1.5 rounded-full"
            :class="g.status === 'online' ? 'bg-ok' : g.status === 'degraded' ? 'bg-warn' : 'bg-ko'"
          />
        </span>
        <span
          v-else-if="badge(item.key)"
          class="rounded px-[5px] font-mono text-[10.5px] font-semibold"
          :class="{
            'bg-ko-bg text-ko': badge(item.key)!.tone === 'ko',
            'bg-warn-bg text-warn': badge(item.key)!.tone === 'warn',
            'bg-sub text-text2': badge(item.key)!.tone === 'neutral',
          }"
        >{{ badge(item.key)!.text }}</span>
        <kbd
          v-if="item.keys && item.key !== 'gateways'"
          class="font-mono text-[10.5px] text-text3"
        >{{ item.keys }}</kbd>
      </NuxtLink>
    </div>

    <div class="mt-auto flex flex-col gap-2">
      <div class="flex flex-col gap-[5px] rounded-lg border border-line bg-code p-[10px]">
        <span class="font-mono text-[10.5px] text-text3">{{ t('nav.alsoBy') }}</span>
        <code class="font-mono text-[11.5px]"><span class="text-text3">cli</span> afw login</code>
        <code class="font-mono text-[11.5px]"><span class="text-text3">mcp</span> afw-admin</code>
        <code class="font-mono text-[11.5px]"><span class="text-text3">api</span> /v1 · openapi</code>
      </div>
      <UDropdownMenu
        :items="userMenu"
        :content="{ side: 'top', align: 'start' }"
      >
        <button
          type="button"
          class="afw-ghost flex items-center gap-[10px] rounded-lg px-1.5 py-1 text-left"
          data-testid="user-menu"
        >
          <span class="flex size-[26px] items-center justify-center rounded-full bg-pri-bg text-[11px] font-bold text-pri">{{ initials }}</span>
          <span class="flex flex-col leading-[1.25]">
            <span class="text-[12.5px] font-semibold">{{ me?.name }}</span>
            <span class="font-mono text-[10.5px] text-text3">{{ me ? `${t(`role.${me.role}`)} · ${me.auth}` : '' }}</span>
          </span>
        </button>
      </UDropdownMenu>
    </div>
  </nav>
</template>
