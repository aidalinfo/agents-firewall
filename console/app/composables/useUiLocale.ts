import type { UiLocale } from '~/utils/format'

/** Current UI locale narrowed to the locales the formatters know. */
export function useUiLocale() {
  const { locale } = useI18n()
  return computed<UiLocale>(() => (locale.value === 'en' ? 'en' : 'fr'))
}
