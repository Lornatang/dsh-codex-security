import { SecurityService } from '../../lib/service.js'

const [stateDir, targetPath, mode, value] = process.argv.slice(2)
const service = new SecurityService({}, { config: { stateDir } })
await service.store.init()
await service.store.loadIndex()
process.send({ kind: 'ready' })
process.on('message', async (message) => {
  if (message !== 'go') return
  try {
    if (mode === 'create') {
      const result = await service.startScan({ targetPath }, 'standard')
      process.send({ kind: 'done', scanId: result.scanId }, () => process.exit(0))
    } else {
      await service.recordDiscoveryCandidates({ scanId: mode, candidates: [{
        ruleId: `test/worker-${value}`, title: `Candidate ${value}`, severity: 'high', path: 'app.js',
        startLine: 1, anchor: `test/worker-${value}`, summary: 'Candidate submitted from another process.',
      }] })
      process.send({ kind: 'done' }, () => process.exit(0))
    }
  } catch (error) {
    process.send({ kind: 'error', message: String(error?.stack ?? error) }, () => process.exit(1))
  }
})
