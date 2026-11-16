import { readWorkerSource, sourceRootIdentity } from '../../lib/secure-read.js'
const root = sourceRootIdentity(process.argv[2])
try {
  readWorkerSource(root.path, 'victim.js', 1024, root.identity)
  process.stdout.write('unexpected success')
} catch (error) { process.stdout.write(String(error)) }
