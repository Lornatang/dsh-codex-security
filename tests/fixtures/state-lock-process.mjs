import { acquireStateLock } from '../../lib/state-lock.js'

const release = await acquireStateLock(process.argv[2], { timeoutMs: 5000 })
process.send({ kind: 'locked' })
process.on('message', (message) => {
  if (message === 'release') {
    release()
    process.send({ kind: 'released' }, () => process.exit(0))
  }
})
