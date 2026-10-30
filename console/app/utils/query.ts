import type { FlowQuery, Verdict } from '~/api/types'

/** Filters the journal query bar understands (subset of FlowQuery). */
export type QueryFilters = Pick<FlowQuery, 'agent' | 'zone' | 'destination' | 'rule' | 'verdict' | 'q'>

const KEYS: Record<string, keyof QueryFilters> = {
  agent: 'agent',
  zone: 'zone',
  dest: 'destination',
  destination: 'destination',
  règle: 'rule',
  regle: 'rule',
  rule: 'rule',
  verdict: 'verdict',
}

const VERDICTS: Record<string, Verdict> = {
  accepté: 'allow',
  accepte: 'allow',
  accept: 'allow',
  accepted: 'allow',
  allow: 'allow',
  refusé: 'deny',
  refuse: 'deny',
  refused: 'deny',
  deny: 'deny',
  denied: 'deny',
}

/** Splits on spaces, keeping "quoted text" together. */
function words(input: string): string[] {
  const out: string[] = []
  const re = /"([^"]*)"|(\S+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(input)) !== null) out.push(m[1] ?? m[2]!)
  return out
}

/**
 * Parses the journal query bar ("agent:daniel-bot dest:*.exemple.com règle:12 free text") into
 * API filters. Pure syntax: the filtering itself is done by the API.
 */
export function parseQuery(input: string): QueryFilters {
  const filters: QueryFilters = {}
  const free: string[] = []
  for (const word of words(input)) {
    const idx = word.indexOf(':')
    const key = idx > 0 ? KEYS[word.slice(0, idx).toLowerCase()] : undefined
    const value = idx > 0 ? word.slice(idx + 1) : ''
    if (!key || !value) {
      free.push(word)
      continue
    }
    if (key === 'verdict') {
      const v = VERDICTS[value.toLowerCase()]
      if (v) filters.verdict = v
      else free.push(word)
      continue
    }
    filters[key] = value
  }
  if (free.length) filters.q = free.join(' ')
  return filters
}

export interface QueryToken {
  key: keyof QueryFilters
  value: string
}

const ORDER: (keyof QueryFilters)[] = ['agent', 'zone', 'destination', 'rule', 'verdict', 'q']

export function queryTokens(filters: QueryFilters): QueryToken[] {
  return ORDER.filter(k => filters[k]).map(k => ({ key: k, value: String(filters[k]) }))
}
