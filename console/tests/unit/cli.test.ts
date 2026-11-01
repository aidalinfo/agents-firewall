import { describe, expect, it } from 'vitest'
import { allowRuleCli, curlFor, httpReason } from '../../app/utils/cli'

describe('allowRuleCli', () => {
  it('renders the CLI equivalent of the pre-filled rule, every value shell-quoted', () => {
    expect(allowRuleCli({ zone: 'bots-internes', dest: 'dom-api.exemple.com', createObject: true, service: 'https', before: '12', expiresInDays: 30, flowId: 'f-8c21e4' })).toBe(
      "$ afw rule add \\\n    --zone 'bots-internes' \\\n    --dest 'dom-api.exemple.com' --create-object \\\n    --service 'https' --action accept \\\n    --before '12' --expire 30d \\\n    --comment 'flux f-8c21e4'",
    )
  })

  it('cannot be turned into command injection by API values', () => {
    const cli = allowRuleCli({ zone: 'z;rm -rf ~', dest: '$(curl evil)', createObject: false, service: '`id`', before: "1' && touch /tmp/x '", expiresInDays: null, flowId: 'f"; id; "' })
    expect(cli).toContain("--zone 'z;rm -rf ~'")
    expect(cli).toContain("--dest '$(curl evil)'")
    expect(cli).toContain("--service '`id`'")
    expect(cli).toContain("--before '1'\\'' && touch /tmp/x '\\'''")
    expect(cli).toContain("--comment 'flux f\"; id; \"'")
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
      'curl -X \'POST\' \'https://api.exemple.com/v1/upload\' \\\n  -H \'Host: api.exemple.com\' \\\n  -H \'X-Q: it\'\\\'\'s\'',
    )
  })
})

describe('curlFor — injection', () => {
  it('quotes the method too', () => {
    const cmd = curlFor({ method: '`touch /tmp/pwned`', url: 'https://x/', headers: [] })
    expect(cmd).toBe("curl -X '`touch /tmp/pwned`' 'https://x/'")
    expect(curlFor({ method: "POST'; touch /tmp/pwned; '", url: 'https://x/', headers: [] })).toBe("curl -X 'POST'\\''; touch /tmp/pwned; '\\''' 'https://x/'")
  })
})

describe('httpReason', () => {
  it('knows common status codes', () => {
    expect(httpReason(200)).toBe('200 OK')
    expect(httpReason(403)).toBe('403 Forbidden')
    expect(httpReason(599)).toBe('599')
  })
})
