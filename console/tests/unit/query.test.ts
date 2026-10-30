import { describe, expect, it } from 'vitest'
import { parseQuery, queryTokens } from '../../app/utils/query'

describe('parseQuery', () => {
  it('extracts French and English keys and keeps free text', () => {
    expect(parseQuery('agent:daniel-bot dest:*.exemple.com règle:12 upload')).toEqual({
      agent: 'daniel-bot',
      destination: '*.exemple.com',
      rule: '12',
      q: 'upload',
    })
    expect(parseQuery('zone:ops rule:S1 destination:169.254.169.254')).toEqual({
      zone: 'ops',
      rule: 'S1',
      destination: '169.254.169.254',
    })
  })

  it('normalises verdict values in both languages', () => {
    expect(parseQuery('verdict:refusé')).toEqual({ verdict: 'deny' })
    expect(parseQuery('verdict:accepted')).toEqual({ verdict: 'allow' })
    expect(parseQuery('verdict:deny')).toEqual({ verdict: 'deny' })
  })

  it('ignores unknown verdicts and empty values, keeps quoted text', () => {
    expect(parseQuery('verdict:maybe agent:')).toEqual({ q: 'verdict:maybe agent:' })
    expect(parseQuery('"compte rendu" agent:x')).toEqual({ agent: 'x', q: 'compte rendu' })
    expect(parseQuery('   ')).toEqual({})
  })
})

describe('queryTokens', () => {
  it('lists active filters as removable chips', () => {
    expect(queryTokens({ agent: 'daniel-bot', verdict: 'deny', q: 'pdf' })).toEqual([
      { key: 'agent', value: 'daniel-bot' },
      { key: 'verdict', value: 'deny' },
      { key: 'q', value: 'pdf' },
    ])
  })
})
