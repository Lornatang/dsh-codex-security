import { SecurityService } from '../../lib/service.js'
import { DeepCoordinator } from '../../lib/deep-coordinator.js'
import { WorkerRegistry } from '../../lib/deep-worker.js'

const [mode, stateDir, target, scanId, claim, identity = 'owner'] = process.argv.slice(2)
const service = new SecurityService({}, { config: { stateDir } })
if (mode === 'pause-seal') {
  let parentId
  const startScan = service.startScan.bind(service)
  const completeScan = service.completeScan.bind(service)
  service.startScan = async (...args) => {
    const result = await startScan(...args)
    if (args[1] === 'deep') parentId = result.scanId
    return result
  }
  service.completeScan = async (args) => {
    if (args.scanId !== parentId) {
      process.send?.({ type: 'child-seal', childScanId: args.scanId })
      await new Promise(() => {})
    }
    return completeScan(args)
  }
}
if (mode === 'initializing') {
  service.startScan = async (_args, _kind, options) => {
    process.send?.({ type: 'initializing', scanId: options.scanId })
    await new Promise(() => {})
  }
}
const registry = new WorkerRegistry()
const host = {
  async ensureReady() {},
  async start({ childId, signal }) {
    process.send?.({ type: 'worker', childId })
    const result = (async () => {
      if (mode === 'start') await new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }))
      for (const path of registry.list(childId)) registry.acceptRead(childId, path, await registry.read(childId, path))
      return { stopReason: 'completed', structured: { draftJson: JSON.stringify({ findings: [], reviewState: {
        completeness: 'complete', surfaces: [{ label: 'source', disposition: 'no_issue_found' }],
      } }) } }
    })()
    return { childId, result, dispose: async () => {} }
  },
}
const coordinator = new DeepCoordinator(service, registry, host)
try {
  if (mode === 'start' || mode === 'initializing' || mode === 'pause-seal') {
    const started = await coordinator.start({ targetPath: target, workers: 1, maxDiscoveryRuns: 2, stopAfterNoNew: 4 }, { agent: { id: identity } })
    process.send?.({ type: 'started', ...started })
    await coordinator.wait(started.scanId)
    const record = (await service.getScanContext({ scanId: started.scanId })).scan
    process.send?.({ type: 'done', status: record.status, error: record.error })
  } else if (mode === 'cancel') {
    const result = await coordinator.cancel({ scanId, ...(claim ? { recoveryClaim: claim } : {}) }, { agent: { id: identity } })
    process.send?.({ type: 'done', status: result.status })
  } else {
    await coordinator.resume({ scanId, ...(claim ? { recoveryClaim: claim } : {}) }, { agent: { id: identity } })
    await coordinator.wait(scanId)
    const record = (await service.getScanContext({ scanId })).scan
    process.send?.({ type: 'done', status: record.status, error: record.error })
  }
} catch (error) { process.send?.({ type: 'error', error: String(error) }) }
process.disconnect?.()
