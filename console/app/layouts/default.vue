<script setup lang="ts">
import { NAV } from '~/utils/nav'

const { t } = useI18n()
const router = useRouter()
const api = useApi()
const mobileNav = useState('afw-mobile-nav', () => false)
const paletteOpen = useState('afw-palette', () => false)
const shortcutsOpen = ref(false)
const { refresh } = usePolicySession()

onMounted(() => {
  void refresh()
})

watch(() => router.currentRoute.value.fullPath, () => {
  mobileNav.value = false
})

const agents = useAsyncData('palette-agents', () => api.listAgents(), { default: () => [], lazy: true })

const groups = computed(() => [
  {
    id: 'pages',
    label: t('palette.pages'),
    items: NAV.flatMap(g => g.items).map(i => ({ label: t(`nav.${i.key}`), icon: i.icon, suffix: i.keys, to: i.to })),
  },
  {
    id: 'agents',
    label: t('nav.agents'),
    items: agents.data.value.map(a => ({ label: a.agent.name, suffix: `@${a.zone_name}`, icon: 'i-lucide-bot', to: `/agents/${a.agent.id}` })),
  },
  {
    id: 'more',
    label: t('palette.more'),
    items: [
      { label: t('nav.audit'), icon: 'i-lucide-scroll-text', to: '/audit' },
      { label: t('nav.alerts'), icon: 'i-lucide-bell', to: '/alerts' },
    ],
  },
])

function onPick(item: unknown) {
  const to = (item as { to?: string } | undefined)?.to
  if (to) {
    paletteOpen.value = false
    void navigateTo(to)
  }
}

const go = (path: string) => () => navigateTo(path)
defineShortcuts({
  'meta_k': () => (paletteOpen.value = !paletteOpen.value),
  'ctrl_k': () => (paletteOpen.value = !paletteOpen.value),
  'shift_?': () => (shortcutsOpen.value = true),
  'g-j': go('/'),
  'g-a': go('/agents'),
  'g-i': go('/internal'),
  'g-l': go('/alerts'),
  'g-r': go('/rules'),
  'g-o': go('/objects'),
  'g-v': go('/revisions'),
  'g-p': go('/gateways'),
})

const shortcutList = computed(() => [
  ['⌘ K', t('shortcuts.palette')],
  ['g j · g a · g r…', t('shortcuts.goto')],
  ['j / k', t('shortcuts.navigate')],
  ['a', t('shortcuts.allow')],
  ['c', t('shortcuts.curl')],
  ['/', t('shortcuts.search')],
  ['esc', t('shortcuts.close')],
])
</script>

<template>
  <div class="flex min-h-screen flex-col bg-bg text-text">
    <div class="flex flex-1">
      <aside class="sticky top-0 hidden h-screen w-[208px] flex-none md:block">
        <ShellAppSidebar />
      </aside>
      <USlideover
        v-model:open="mobileNav"
        side="left"
        :title="t('nav.aria')"
        :ui="{ content: 'max-w-[240px]', body: 'p-0 sm:p-0' }"
      >
        <template #content>
          <ShellAppSidebar />
        </template>
      </USlideover>
      <main class="grid-bg flex min-w-0 flex-1 flex-col">
        <slot />
      </main>
    </div>
    <ShellStatusBar @shortcuts="shortcutsOpen = true" />

    <UModal
      v-model:open="paletteOpen"
      :title="t('palette.title')"
      :description="t('palette.placeholder')"
      :ui="{ content: 'max-w-xl' }"
    >
      <template #content>
        <UCommandPalette
          :groups="groups"
          :placeholder="t('palette.placeholder')"
          class="h-96"
          @update:model-value="onPick"
        />
      </template>
    </UModal>

    <UModal
      v-model:open="shortcutsOpen"
      :title="t('shortcuts.title')"
    >
      <template #body>
        <dl class="grid grid-cols-[160px_1fr] gap-x-3 gap-y-2 text-[12.5px]">
          <template
            v-for="[k, label] in shortcutList"
            :key="k"
          >
            <dt><kbd class="afw-kbd">{{ k }}</kbd></dt>
            <dd class="m-0 text-text2">
              {{ label }}
            </dd>
          </template>
        </dl>
      </template>
    </UModal>
  </div>
</template>
