import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import type { ValidateFunction } from 'ajv'

const require = createRequire(import.meta.url)
const Ajv2020 = require('ajv/dist/2020.js').default as typeof import('ajv/dist/2020.js').Ajv2020
const addFormats = require('ajv-formats').default as typeof import('ajv-formats').default

type ArtifactKind = 'findings' | 'coverage' | 'scan-manifest'
const validators = new Map<ArtifactKind, ValidateFunction>()
const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)

export function compileToolArguments(schema: object): (value: unknown) => void {
  const validate = ajv.compile(schema)
  return (value: unknown) => {
    if (!validate(value)) {
      const details = (validate.errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`).join('; ')
      throw new Error('codex-security: invalid tool arguments: ' + details)
    }
  }
}

/** Validate the exact documents shipped by this package before publishing a seal. */
export function assertArtifactContract(kind: ArtifactKind, value: unknown): void {
  let validate = validators.get(kind)
  if (!validate) {
    const schema = JSON.parse(readFileSync(new URL('../schemas/' + kind + '.schema.json', import.meta.url), 'utf8')) as object
    const compiled: ValidateFunction = ajv.compile(schema)
    validators.set(kind, compiled)
    validate = compiled
  }
  if (!validate(value)) {
    const details = (validate.errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`).join('; ')
    throw new Error('codex-security: invalid ' + kind + ' artifact: ' + details)
  }
}
