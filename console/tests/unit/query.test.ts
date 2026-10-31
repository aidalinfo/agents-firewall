import { describe, expect, it } from 'vitest'
import { parseQuery, queryTokens, toFlowQuery } from '../../app/utils/query'

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

describe('toFlowQuery', () => {
  const dir = {
    agents: [{ id: '30000000-0000-4000-8000-000000000001', name: 'daniel-bot' }],
    zones: [{ id: '20000000-0000-4000-8000-000000000001', name: 'bots-internes' }],
    rules: [{ id: '80000000-0000-4000-8000-000000000012', number: 12 }],
  }

  it('resolves names and rule numbers to the ids of the API filters', () => {
    expect(toFlowQuery({ agent: 'daniel-bot', zone: 'bots-internes', rule: '12', destination: '*.exemple.com', q: 'pdf' }, dir)).toEqual({
      agent: '30000000-0000-4000-8000-000000000001',
      zone: '20000000-0000-4000-8000-000000000001',
      rule: '80000000-0000-4000-8000-000000000012',
      destination: '*.exemple.com',
      q: 'pdf',
    })
  })

  it('keeps an unknown name as a filter that matches nothing, and passes ids through', () => {
    expect(toFlowQuery({ agent: 'inconnu' }, dir).agent).toBe('00000000-0000-0000-0000-000000000000')
    expect(toFlowQuery({ zone: '20000000-0000-4000-8000-000000000009' }, dir).zone).toBe('20000000-0000-4000-8000-000000000009')
    expect(toFlowQuery({}, dir)).toEqual({})
  })
})
