/**
 * Runtime validation against the JSON schemas of the contract (docs/api/openapi.yaml), shared by
 * the console tests (mock answers) and the e2e contract test (real API answers): the compile-time
 * types are generated, this checks the values actually exchanged.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import Ajv2020 from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import { parse } from 'yaml'
import type { components } from '../../app/api/schema'

const spec = parse(readFileSync(resolve(__dirname, '../../../docs/api/openapi.yaml'), 'utf8')) as Record<string, unknown>

/**
 * Strict mode: an object schema with `properties` admits no undeclared field (most generated
 * schemas leave `additionalProperties` open), so a field invented by the console mock — or
 * returned by the API without being in the contract — fails the test.
 */
function strict(node: unknown): void {
  if (Array.isArray(node)) return node.forEach(strict)
  if (!node || typeof node !== 'object') return
  const o = node as Record<string, unknown>
  if (o.properties && o.additionalProperties === undefined && o.unevaluatedProperties === undefined) o.unevaluatedProperties = false
  Object.values(o).forEach(strict)
}
strict((spec.components as Record<string, unknown>).schemas)

const ajv = new Ajv2020({ strict: false, allErrors: true })
addFormats(ajv)
for (const f of ['uint8', 'uint16', 'uint32', 'uint64', 'int32', 'int64', 'double', 'float', 'ip']) ajv.addFormat(f, true)
ajv.addSchema({ ...(spec as object), $id: 'afw' }, 'afw')

export type SchemaName = keyof components['schemas']

/** Throws with readable errors when `value` does not match `components.schemas[name]`. */
export function assertSchema(name: SchemaName, value: unknown): void {
  const validate = ajv.getSchema(`afw#/components/schemas/${name}`)
  if (!validate) throw new Error(`unknown schema ${name}`)
  if (!validate(value)) {
    throw new Error(`${name} does not match the contract: ${ajv.errorsText(validate.errors, { separator: '\n' })}\n${JSON.stringify(value).slice(0, 400)}`)
  }
}

/** Same for an array of `name`. */
export function assertSchemaArray(name: SchemaName, values: unknown[]): void {
  for (const v of values) assertSchema(name, v)
}
