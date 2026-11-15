import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { SecurityService } from '../../lib/service.js'

const [root] = process.argv.slice(2)
const target = join(root, 'workspace')
await mkdir(target)
await writeFile(join(target, 'input.txt'), 'hello')
const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
const scan = await service.startScan({ targetPath: target }, 'standard')
await service.recordScanDraft({ scanId: scan.scanId, findings: [], complete: true, reviewState: { surfaces: [{ label: 'source', disposition: 'no_issue_found' }], explicitExclusions: [], deferred: [] } })
await service.completeScan({ scanId: scan.scanId })
const result = await service.exportFindings({ scanId: scan.scanId, format: 'json' })
process.stdout.write(JSON.stringify({ kind: scan.scan.target.kind, content: await readFile(result.path, 'utf8') }))
