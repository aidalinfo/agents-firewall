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

  icon: {
    serverBundle: 'local',
    clientBundle: { scan: true },
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
