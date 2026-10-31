import type { FlowEvent } from '~/api/types'

/** UI locales supported by the console. */
export type UiLocale = 'fr' | 'en'

const DASH = '—'

const BYTE_UNITS: Record<UiLocale, string[]> = {
  fr: ['o', 'Ko', 'Mo', 'Go', 'To'],
  en: ['B', 'kB', 'MB', 'GB', 'TB'],
}

function decimal(value: number, locale: UiLocale): string {
  const digits = value < 10 && !Number.isInteger(Math.round(value * 10) / 10) ? 1 : 0
  return new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: 0 }).format(
    digits ? Math.round(value * 10) / 10 : Math.round(value),
  )
}

/** Decimal (SI) byte sizes, as shown in the mockup: "312 o", "9,4 Ko", "4,1 Mo". */
export function formatBytes(bytes: number | null | undefined, locale: UiLocale): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return DASH
  const units = BYTE_UNITS[locale]
  let value = bytes
  let unit = 0
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit++
  }
  if (unit === 0) return `${Math.round(value)} ${units[0]}`
  return `${decimal(value, locale)} ${units[unit]}`
}

/** "84 ms", "6,2 s", "42 s", "4 min". */
export function formatDuration(ms: number | null | undefined, locale: UiLocale): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return DASH
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${decimal(ms / 1000, locale)} s`
  return `${Math.round(ms / 60_000)} min`
}

export function formatNumber(value: number | null | undefined, locale: UiLocale): string {
  if (value == null || !Number.isFinite(value)) return DASH
  return new Intl.NumberFormat(locale).format(value)
}

const pad = (v: number, len = 2) => String(v).padStart(len, '0')

/** Local wall-clock time "14:32:07" (or "14:32:07.412"). */
export function formatTime(iso: string | null | undefined, opts: { ms?: boolean, seconds?: boolean } = {}): string {
  if (!iso) return DASH
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return DASH
  const base = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  if (opts.seconds === false) return base
  const withSec = `${base}:${pad(d.getSeconds())}`
  return opts.ms ? `${withSec}.${pad(d.getMilliseconds(), 3)}` : withSec
}

/** "30/10 11:02" (fr) or "10/30 11:02" (en). */
export function formatDateTime(iso: string | null | undefined, locale: UiLocale): string {
  if (!iso) return DASH
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return DASH
  const day = locale === 'fr' ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : `${pad(d.getMonth() + 1)}/${pad(d.getDate())}`
  return `${day} ${formatTime(iso, { seconds: false })}`
}

/** "29/11/2026" (fr) or "11/29/2026" (en). */
export function formatDate(iso: string | null | undefined, locale: UiLocale): string {
  if (!iso) return DASH
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return DASH
  return locale === 'fr'
    ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`
    : `${pad(d.getMonth() + 1)}/${pad(d.getDate())}/${d.getFullYear()}`
}

const RELATIVE_STEPS: [string, number][] = [
  ['s', 60],
  ['min', 60],
  ['h', 24],
  ['d', Number.POSITIVE_INFINITY],
]

const RELATIVE_UNITS: Record<UiLocale, Record<string, string>> = {
  fr: { s: 's', min: 'min', h: 'h', d: 'j' },
  en: { s: 's', min: 'min', h: 'h', d: 'd' },
}

/** "il y a 20 s", "il y a 6 min" / "20 s ago" — compact style of the mockup. */
export function formatRelative(iso: string | null | undefined, locale: UiLocale, now: Date = new Date()): string {
  if (!iso) return locale === 'fr' ? 'jamais' : 'never'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return DASH
  let delta = Math.max(0, Math.round((now.getTime() - then) / 1000))
  let unit = 's'
  for (const [u, size] of RELATIVE_STEPS) {
    unit = u
    if (delta < size) break
    delta = Math.floor(delta / size)
  }
  const label = `${delta} ${RELATIVE_UNITS[locale][unit]}`
  return locale === 'fr' ? `il y a ${label}` : `${label} ago`
}

/**
 * Label of the rule that decided a flow, in the API's convention (`FlowListItem.rule_label`):
 * `12 · name`, `socle · name` (baseline rule without number), `default-deny`. Used where the
 * contract gives the decision only (flow detail, agent view).
 */
export function flowRuleLabel(flow: Pick<FlowEvent, 'decision' | 'verdict'>): string {
  const d = flow.decision
  if (d.rule_number != null) return `${d.rule_number} · ${d.rule_name}`
  if (d.layer === 'baseline') return `socle · ${d.rule_name}`
  if (d.layer === 'implicit' && flow.verdict === 'deny') return 'default-deny'
  if (d.rule_name) return d.rule_name
  return flow.verdict === 'deny' ? 'default-deny' : 'implicit'
}

/** Short flow identifier shown in the journal: "f-8c21e4". */
export function shortFlowId(id: string): string {
  return `f-${id.replace(/-/g, '').slice(0, 6)}`
}

export type Tone = 'ok' | 'ko' | 'obs' | 'warn' | 'neutral'

export function verdictTone(flow: Pick<FlowEvent, 'verdict' | 'observed'>): Tone {
  if (flow.observed) return 'obs'
  return flow.verdict === 'allow' ? 'ok' : 'ko'
}

/** CSS variables for a tone: foreground and background. */
export function toneVars(tone: Tone): { fg: string, bg: string } {
  switch (tone) {
    case 'ok': return { fg: 'var(--ok)', bg: 'var(--ok-bg)' }
    case 'ko': return { fg: 'var(--ko)', bg: 'var(--ko-bg)' }
    case 'obs': return { fg: 'var(--obs)', bg: 'var(--obs-bg)' }
    case 'warn': return { fg: 'var(--warn)', bg: 'var(--warn-bg)' }
    default: return { fg: 'var(--text2)', bg: 'var(--sub)' }
  }
}

/** Host part of "ip:port" or "[v6]:port". */
export function splitSocket(addr: string): { host: string, port: string } {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(addr)
  return m ? { host: m[1]!, port: m[2]! } : { host: addr, port: '' }
}
