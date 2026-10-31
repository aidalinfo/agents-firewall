import type { Detector, PortRange } from '~/api/types'

/**
 * Text ⇄ structure helpers of the forms. They only translate what the user typed into the
 * contract's shapes (no policy rule is checked here: the API validates and its message is shown).
 */

/** "443, 8000-8100" → [{443,443},{8000,8100}]; "" → [] (any port); null when not numbers. */
export function parsePorts(text: string): PortRange[] | null {
  const out: PortRange[] = []
  for (const part of text.split(',').map(p => p.trim()).filter(Boolean)) {
    const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(part)
    if (!m) return null
    const start = Number(m[1])
    const end = Number(m[2] ?? m[1])
    out.push({ start, end })
  }
  return out
}

export function formatPorts(ports: PortRange[]): string {
  return ports.map(p => (p.start === p.end ? String(p.start) : `${p.start}-${p.end}`)).join(', ')
}

/** One detector per line: `builtin:aws_access_key` or `regex:name=pattern`. */
export function parseDetectors(text: string): Detector[] | null {
  const out: Detector[] = []
  for (const line of text.split('\n').map(l => l.trim()).filter(Boolean)) {
    const builtin = /^builtin:(\S+)$/.exec(line)
    if (builtin) {
      out.push({ type: 'builtin', id: builtin[1]! })
      continue
    }
    const regex = /^regex:([^=]+)=(.+)$/.exec(line)
    if (!regex) return null
    out.push({ type: 'regex', name: regex[1]!.trim(), pattern: regex[2]! })
  }
  return out
}

export function formatDetectors(detectors: Detector[]): string {
  return detectors.map(d => (d.type === 'builtin' ? `builtin:${d.id}` : `regex:${d.name}=${d.pattern}`)).join('\n')
}

/** `<input type="date">` value ⇄ RFC 3339 (end of that day, UTC). */
export function dateToIso(date: string): string | null {
  return date ? `${date}T23:59:59Z` : null
}

export function isoToDate(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : ''
}

/**
 * Random UUID v4 for a resource created by the console (the contract has the client choose the
 * id). `crypto.randomUUID` only exists in secure contexts; `getRandomValues` exists everywhere.
 */
export function newUuid(): string {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  b[6] = (b[6]! & 0x0F) | 0x40
  b[8] = (b[8]! & 0x3F) | 0x80
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}
