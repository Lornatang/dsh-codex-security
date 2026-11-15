import { writeSecureExport } from '../../lib/secure-export.js'

const [output, kind] = process.argv.slice(2)
try {
  const path = await writeSecureExport({ requestedOutput: output, requested: kind !== 'default', scanId: 'cs_test', extension: 'json', content: '{"valid":true}', validate: async () => {} })
  process.stdout.write(JSON.stringify({ ok: true, path }))
} catch (error) { process.stdout.write(JSON.stringify({ ok: false, code: error.code, message: error.message })) }
