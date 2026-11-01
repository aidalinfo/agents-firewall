import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = resolve(__dirname, '../..')

describe('generated API types', () => {
  it('app/api/schema.d.ts is up to date with docs/api/openapi.yaml (run `pnpm gen:api`)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'afw-schema-'))
    try {
      const out = join(dir, 'schema.d.ts')
      execFileSync(join(root, 'node_modules/.bin/openapi-typescript'), ['../docs/api/openapi.yaml', '-o', out], { cwd: root, stdio: 'pipe' })
      expect(readFileSync(join(root, 'app/api/schema.d.ts'), 'utf8')).toBe(readFileSync(out, 'utf8'))
    }
    finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 30_000)
})
