import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

type Tree = { [k: string]: string | Tree }
const root = join(__dirname, '../..')
const load = (lang: string) => JSON.parse(readFileSync(join(root, 'i18n/locales', `${lang}.json`), 'utf8')) as Tree

function flatten(tree: Tree, prefix = ''): Record<string, string> {
  return Object.entries(tree).reduce<Record<string, string>>((acc, [k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k
    return typeof v === 'string' ? { ...acc, [key]: v } : { ...acc, ...flatten(v, key) }
  }, {})
}

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? sources(p) : /\.(vue|ts)$/.test(f) ? [p] : []
  })
}

const fr = flatten(load('fr'))
const en = flatten(load('en'))

describe('i18n', () => {
  it('has the same keys in French and English', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(fr).sort())
  })

  it('has no empty message and no HTML (refused by the message compiler)', () => {
    for (const [k, v] of [...Object.entries(fr), ...Object.entries(en)]) {
      expect(v, k).not.toBe('')
      expect(v, k).not.toMatch(/<[a-z/][^>]*>/i)
    }
  })

  it('keeps the same placeholders and plural forms in both languages', () => {
    const vars = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
    for (const k of Object.keys(fr)) {
      expect(new Set(vars(en[k]!)), k).toEqual(new Set(vars(fr[k]!)))
      expect(en[k]!.split(' | ').length, k).toBe(fr[k]!.split(' | ').length)
    }
  })

  it('defines every key the app uses', () => {
    const missing: string[] = []
    for (const file of sources(join(root, 'app'))) {
      const code = readFileSync(file, 'utf8')
      for (const m of code.matchAll(/\bte?\(\s*['`]([\w.${}-]+)['`]/g)) {
        const key = m[1]!
        if (key.includes('${')) {
          const prefix = key.slice(0, key.indexOf('${'))
          if (!Object.keys(fr).some(k => k.startsWith(prefix))) missing.push(`${key} (${file})`)
        }
        else if (!(key in fr)) missing.push(`${key} (${file})`)
      }
      for (const m of code.matchAll(/keypath="([\w.]+)"/g)) if (!(m[1]! in fr)) missing.push(m[1]!)
    }
    expect(missing).toEqual([])
  })
})
