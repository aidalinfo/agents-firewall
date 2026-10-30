<script setup lang="ts">
import { createOidcState, safeRedirect, takeOidcState } from '~/utils/security'

definePageMeta({ layout: 'auth' })

const { t, locale } = useI18n()
const switchLocale = useSwitchLocale()
const api = useApi()
const route = useRoute()
const { login } = useAuth()
const mode = useNuxtApp().$apiMode

const token = ref('')
const busy = ref(false)
const error = ref<string | null>(null)

useHead({ title: () => `${t('login.title')} — agents-firewall` })

const redirect = computed(() => safeRedirect(route.query.redirect, window.location.origin))

async function withToken(value: string, target = redirect.value) {
  busy.value = true
  error.value = null
  try {
    await login(value)
    await navigateTo(safeRedirect(target, window.location.origin))
  }
  catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  }
  finally {
    busy.value = false
  }
}

function oidc() {
  // Anti-CSRF: random state kept in sessionStorage, checked on the way back.
  const state = createOidcState(redirect.value, sessionStorage)
  const url = api.oidcLoginUrl(`${window.location.origin}/login`, state)
  if (url) window.location.href = url
  // Mock mode: no identity provider, the demo session stands for an OIDC login.
  else void withToken('demo-oidc-session', takeOidcState(state, sessionStorage).redirect)
}

// OIDC callback: the control plane redirects back with #access_token=…&state=… (never in the query string).
onMounted(() => {
  const hash = new URLSearchParams(window.location.hash.slice(1))
  const accessToken = hash.get('access_token')
  if (!accessToken) return
  history.replaceState(null, '', window.location.pathname + window.location.search)
  const check = takeOidcState(hash.get('state'), sessionStorage)
  if (!check.ok) {
    error.value = t('login.badState')
    return
  }
  void withToken(accessToken, check.redirect)
})
</script>

<template>
  <div class="afw-card flex w-full max-w-[400px] flex-col gap-5 p-6">
    <div class="flex items-center gap-[10px]">
      <span class="flex size-8 items-center justify-center rounded-lg bg-pri text-pri-fg">
        <UIcon
          name="i-lucide-shield-check"
          class="size-[18px]"
        />
      </span>
      <span class="flex flex-col leading-[1.2]">
        <strong class="text-[15px] font-[650]">agents-firewall</strong>
        <span class="font-mono text-[11px] text-text3">{{ t('login.subtitle') }}</span>
      </span>
      <span class="flex-1" />
      <button
        type="button"
        class="afw-ghost rounded-md px-2 py-1 font-mono text-[11px] text-text2"
        @click="switchLocale(locale === 'fr' ? 'en' : 'fr')"
      >
        {{ locale === 'fr' ? 'EN' : 'FR' }}
      </button>
    </div>

    <div class="flex flex-col gap-1">
      <h1 class="m-0 text-lg font-[650]">
        {{ t('login.title') }}
      </h1>
      <p class="m-0 text-[12.5px] text-text2">
        {{ t('login.intro') }}
      </p>
    </div>

    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-alert"
      :title="t('login.failed')"
      :description="error"
    />

    <UButton
      block
      size="lg"
      icon="i-lucide-log-in"
      :loading="busy"
      class="bg-pri font-[650] text-pri-fg hover:bg-pri/90"
      data-testid="login-oidc"
      @click="oidc"
    >
      {{ t('login.oidc') }}
    </UButton>

    <div class="flex items-center gap-3 text-[11px] text-text3">
      <span class="h-px flex-1 bg-line" />{{ t('login.or') }}<span class="h-px flex-1 bg-line" />
    </div>

    <form
      class="flex flex-col gap-2"
      @submit.prevent="withToken(token)"
    >
      <label
        for="afw-token"
        class="text-xs font-semibold"
      >{{ t('login.token') }}</label>
      <UInput
        id="afw-token"
        v-model="token"
        type="password"
        autocomplete="off"
        :placeholder="t('login.tokenPlaceholder')"
        class="font-mono"
        data-testid="login-token"
      />
      <span class="text-[11.5px] text-text3">{{ t('login.tokenHelp') }}</span>
      <UButton
        type="submit"
        block
        variant="outline"
        color="neutral"
        :disabled="!token"
        :loading="busy"
      >
        {{ t('login.useToken') }}
      </UButton>
    </form>

    <p
      v-if="mode === 'mock'"
      class="m-0 rounded-lg bg-obs-bg px-3 py-2 text-[11.5px] text-obs"
    >
      {{ t('login.demo') }}
    </p>
  </div>
</template>
