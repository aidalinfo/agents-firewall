// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-10-01',
  // The console is a pure client of the control-plane API (bearer token kept in
  // sessionStorage): no server-side rendering, Nitro only serves the SPA (ADR 0014).
  ssr: false,
  devtools: { enabled: false },
  devServer: { host: '0.0.0.0', port: 3000 },

  modules: ['@nuxt/ui', '@nuxt/eslint', '@nuxtjs/i18n'],

  css: ['~/assets/css/main.css'],

  app: {
    head: {
      title: 'agents-firewall',
      htmlAttrs: { lang: 'fr' },
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
  },

  colorMode: {
    preference: 'dark',
    fallback: 'dark',
    storageKey: 'afw-color-mode',
  },

  fonts: {
    families: [
      { name: 'Geist', provider: 'google', weights: [400, 500, 600, 700] },
      { name: 'Geist Mono', provider: 'google', weights: [400, 500, 600, 700] },
    ],
  },

  // Every icon is bundled: the strict CSP forbids fetching icons from api.iconify.design at runtime.
  icon: {
    serverBundle: 'local',
    fallbackToApi: false,
    clientBundle: {
      scan: true,
      icons: [
        'lucide:align-left',
        'lucide:arrow-right',
        'lucide:bell',
        'lucide:bot',
        'lucide:check',
        'lucide:chevron-down',
        'lucide:chevrons-up-down',
        'lucide:circle-alert',
        'lucide:clipboard-check',
        'lucide:code',
        'lucide:copy',
        'lucide:download',
        'lucide:history',
        'lucide:languages',
        'lucide:layout-grid',
        'lucide:lock',
        'lucide:log-in',
        'lucide:log-out',
        'lucide:maximize-2',
        'lucide:menu',
        'lucide:moon',
        'lucide:pause',
        'lucide:play',
        'lucide:plus',
        'lucide:radio',
        'lucide:refresh-cw',
        'lucide:scroll-text',
        'lucide:search',
        'lucide:send',
        'lucide:server',
        'lucide:share-2',
        'lucide:shield',
        'lucide:shield-alert',
        'lucide:shield-check',
        'lucide:sun',
        'lucide:terminal',
        'lucide:undo-2',
        'lucide:x',
        'lucide:chevron-up',
        'lucide:chevron-left',
        'lucide:chevron-right',
        'lucide:loader-circle',
        'lucide:minus',
        'lucide:ellipsis',
        'lucide:arrow-left',
        'lucide:info',
        'lucide:triangle-alert',
        'lucide:circle-check',
        'lucide:circle-x',
        'lucide:eye',
        'lucide:eye-off',
        'lucide:rotate-ccw',
        'lucide:chevrons-left',
        'lucide:chevrons-right',
        'lucide:grip-vertical',
        'lucide:panel-left-open',
        'lucide:panel-left-close',
        'lucide:arrow-up',
        'lucide:arrow-down',
        'lucide:arrow-up-down',
        'lucide:settings',
        'lucide:pencil',
        'lucide:trash-2',
        'lucide:key-round',
        'lucide:move',
        'lucide:hourglass',
      ],
    },
  },

  typescript: {
    strict: true,
    typeCheck: false,
  },

  i18n: {
    defaultLocale: 'fr',
    strategy: 'no_prefix',
    // French by default whatever the browser says; the choice is remembered (plugins/locale.client.ts).
    detectBrowserLanguage: false,
    locales: [
      { code: 'fr', language: 'fr-FR', file: 'fr.json', name: 'Français' },
      { code: 'en', language: 'en-US', file: 'en.json', name: 'English' },
    ],
  },

  runtimeConfig: {
    // Server only. Origin of afw-api to relay /api/** and /healthz to, so that the browser stays on
    // one origin (no CORS, CSP connect-src 'self') — NUXT_API_PROXY_TARGET, e.g. http://afw-api:8080.
    apiProxyTarget: '',
    // Origin of the OIDC provider's token endpoint, added to the CSP connect-src — NUXT_OIDC_CONNECT_SRC.
    oidcConnectSrc: '',
    public: {
      // mock | http — NUXT_PUBLIC_API_MODE
      apiMode: 'mock',
      // Control-plane origin, without /api/v1 — NUXT_PUBLIC_API_BASE
      apiBase: '',
      // Simulated latency of the mock API (ms) — NUXT_PUBLIC_MOCK_LATENCY_MS
      mockLatencyMs: 120,
    },
  },

  nitro: {
    preset: 'node-server',
  },

  eslint: {
    config: { stylistic: false },
  },
})
