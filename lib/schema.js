import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Ajv2020 = require('ajv/dist/2020.js').default;
const addFormats = require('ajv-formats').default;
const validators = new Map();
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
export function compileToolArguments(schema) {
    const validate = ajv.compile(schema);
    return (value) => {
        if (!validate(value)) {
            const details = (validate.errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`).join('; ');
            throw new Error('codex-security: invalid tool arguments: ' + details);
        }
    };
}
/** Validate the exact documents shipped by this package before publishing a seal. */
export function assertArtifactContract(kind, value) {
    let validate = validators.get(kind);
    if (!validate) {
        const schema = JSON.parse(readFileSync(new URL('../schemas/' + kind + '.schema.json', import.meta.url), 'utf8'));
        const compiled = ajv.compile(schema);
        validators.set(kind, compiled);
        validate = compiled;
    }
    if (!validate(value)) {
        const details = (validate.errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`).join('; ');
        throw new Error('codex-security: invalid ' + kind + ' artifact: ' + details);
    }
}
