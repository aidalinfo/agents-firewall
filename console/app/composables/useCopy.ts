/** Copies text to the clipboard and confirms with a toast. */
export function useCopy() {
  const toast = useToast()
  const { t } = useI18n()
  return async (text: string, what?: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.add({ title: t('common.copied'), description: what, icon: 'i-lucide-clipboard-check', duration: 2000 })
    }
    catch {
      toast.add({ title: t('common.copyFailed'), color: 'error', duration: 3000 })
    }
  }
}
