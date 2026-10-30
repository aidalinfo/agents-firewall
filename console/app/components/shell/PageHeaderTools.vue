<script setup lang="ts">
const { t } = useI18n()
const colorMode = useColorMode()
const { changeCount } = usePolicySession()
const mobileNav = useState('afw-mobile-nav', () => false)

function toggleTheme() {
  colorMode.preference = colorMode.value === 'dark' ? 'light' : 'dark'
}
</script>

<template>
  <NuxtLink
    to="/rules"
    class="inline-flex h-8 items-center gap-2 rounded-lg border px-[11px] font-mono text-[11.5px] font-medium no-underline"
    :class="changeCount ? 'border-warn bg-warn-bg' : 'border-line bg-transparent'"
    :style="{ color: changeCount ? 'var(--warn)' : 'var(--text2)' }"
    data-testid="session-pill"
  >
    <UIcon
      name="i-lucide-lock"
      class="size-[13px]"
    />
    {{ t('session.pill', { label: changeCount ? t('session.changes', changeCount) : t('session.empty') }) }}
  </NuxtLink>
  <button
    type="button"
    class="afw-ghost flex size-8 items-center justify-center rounded-lg !border-line text-text2"
    :aria-label="t('theme.toggle')"
    data-testid="theme-toggle"
    @click="toggleTheme"
  >
    <UIcon
      :name="colorMode.value === 'dark' ? 'i-lucide-moon' : 'i-lucide-sun'"
      class="size-[15px]"
    />
  </button>
  <button
    type="button"
    class="afw-ghost flex size-8 items-center justify-center rounded-lg md:hidden"
    :aria-label="t('nav.open')"
    @click="mobileNav = true"
  >
    <UIcon
      name="i-lucide-menu"
      class="size-4"
    />
  </button>
</template>
