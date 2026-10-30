import { describe, expect, it } from 'vitest'
import { allowRuleCli, curlFor, httpReason } from '../../app/utils/cli'

describe('allowRuleCli', () => {
  it('renders the CLI equivalent of the pre-filled rule', () => {
    expect(allowRuleCli({ zone: 'bots-internes', dest: 'dom-api.exemple.com', createObject: true, service: 'https', before: '12', expiresInDays: 30, flowId: 'f-8c21e4' })).toBe(
      '$ afw rule add \\\n    --zone bots-internes \\\n    --dest dom-api.exemple.com --create-object \\\n    --service https --action accept \\\n    --before 12 --expire 30d \\\n    --comment "flux f-8c21e4"',
    )
  })

  it('omits expiry and object creation when not needed', () => {
    const cli = allowRuleCli({ zone: 'z', dest: 'grp-x', createObject: false, service: 'ssh', before: '31', expiresInDays: null, flowId: 'f-1' })
    expect(cli).not.toContain('--expire')
    expect(cli).not.toContain('--create-object')
  })
})

describe('curlFor', () => {
  it('replays the request with masked headers and quotes', () => {
    expect(curlFor({ method: 'POST', url: 'https://api.exemple.com/v1/upload', headers: [['Host', 'api.exemple.com'], ['X-Q', 'it\'s']] })).toBe(
      'curl -X POST \'https://api.exemple.com/v1/upload\' \\\n  -H \'Host: api.exemple.com\' \\\n  -H \'X-Q: it\'\\\'\'s\'',
    )
  })
})

describe('httpReason', () => {
  it('knows common status codes', () => {
    expect(httpReason(200)).toBe('200 OK')
    expect(httpReason(403)).toBe('403 Forbidden')
    expect(httpReason(599)).toBe('599')
  })
})
