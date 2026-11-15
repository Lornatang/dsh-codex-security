import { readdir, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const [directory] = process.argv.slice(2)
const name = (await readdir(directory)).find((entry) => /^\.\d+\.[0-9a-f]+\.tmp$/.test(entry))
if (!name) { process.stdout.write('no-stage'); process.exit(0) }
try {
  await rename(join(directory, name), join(directory, name + '.moved'))
  await writeFile(join(directory, name), 'ATTACKER')
  process.stdout.write('swapped')
} catch (error) { process.stdout.write(String(error.code ?? error)) }
