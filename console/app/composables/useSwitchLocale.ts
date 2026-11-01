export const LOCALE_KEY = 'afw-locale'

/** Switches the UI language and remembers it for the next visits. */
export function useSwitchLocale() {
  const { setLocale } = useI18n()
  return async (code: 'fr' | 'en') => {
    await setLocale(code)
    try {
      localStorage.setItem(LOCALE_KEY, code)
    }
    catch {
      // storage unavailable
    }
    useHead({ htmlAttrs: { lang: code } })
  }
}
