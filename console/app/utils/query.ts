import type { FlowQuery, Uuid, Verdict } from '~/api/types'

/**
 * Filters the journal query bar understands, as typed by the user: agent and zone by name, rule
 * by its displayed number. `toFlowQuery` turns them into the ids of the API's FlowQuery.
 */
export interface QueryFilters {
  agent?: string
  zone?: string
  destination?: string
  rule?: string
  verdict?: Verdict
  q?: string
}

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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

interface Named { id: Uuid, name: string }

/**
 * Resolves names typed in the query bar to the ids expected by `GET /logs/flows` (lists from the
 * API). An unknown name keeps the filter impossible to satisfy instead of silently dropping it.
 */
export function toFlowQuery(f: QueryFilters, dir: { agents: Named[], zones: Named[], rules?: { id: Uuid, number: number }[] }): FlowQuery {
  const NONE = '00000000-0000-0000-0000-000000000000'
  const resolve = (v: string | undefined, list: Named[]) => (v === undefined ? undefined : UUID.test(v) ? v : list.find(x => x.name === v)?.id ?? NONE)
  const wanted = f.rule
  const rule = wanted === undefined
    ? undefined
    : UUID.test(wanted) ? wanted : dir.rules?.find(r => String(r.number) === wanted.replace(/^#/, ''))?.id ?? NONE
  const out: FlowQuery = {
    agent: resolve(f.agent, dir.agents),
    zone: resolve(f.zone, dir.zones),
    rule,
    destination: f.destination,
    verdict: f.verdict,
    q: f.q,
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined)) as FlowQuery
}
