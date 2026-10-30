import { LOCALE_KEY } from '~/composables/useSwitchLocale'

function savedLocale(): string | null {
  try {
    return localStorage.getItem(LOCALE_KEY)
  }
  catch {
    return null
  }
}

/** Restores the language chosen by the user (French by default). */
export default defineNuxtPlugin(async (nuxtApp) => {
  const saved = savedLocale()
  if (saved === 'en' || saved === 'fr') await nuxtApp.$i18n.setLocale(saved)
})
