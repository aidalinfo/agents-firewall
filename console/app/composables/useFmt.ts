import {
  formatBytes,
  formatDate,
  formatDateTime,
  formatDuration,
  formatNumber,
  formatRelative,
  formatTime,
} from '~/utils/format'

/** Locale-bound formatters for templates. */
export function useFmt() {
  const loc = useUiLocale()
  return {
    bytes: (v: number | null | undefined) => formatBytes(v, loc.value),
    duration: (v: number | null | undefined) => formatDuration(v, loc.value),
    num: (v: number | null | undefined) => formatNumber(v, loc.value),
    rel: (v: string | null | undefined) => formatRelative(v, loc.value),
    time: (v: string | null | undefined, ms = false) => formatTime(v, { ms }),
    hm: (v: string | null | undefined) => formatTime(v, { seconds: false }),
    dateTime: (v: string | null | undefined) => formatDateTime(v, loc.value),
    date: (v: string | null | undefined) => formatDate(v, loc.value),
  }
}
