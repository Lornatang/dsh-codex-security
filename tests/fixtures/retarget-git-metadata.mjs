import { open, writeFile } from 'node:fs/promises'

const [mode, file, directory] = process.argv.slice(2)
const target = directory.replaceAll('\\', '/')
if (mode === 'gitfile') {
  // Git marks .git files hidden on Windows; OPEN_EXISTING works there.
  const handle = await open(file, 'r+')
  try { await handle.truncate(0); await handle.writeFile(`gitdir: ${target}\n`) } finally { await handle.close() }
} else {
  await writeFile(file, `${target}\n`)
}
