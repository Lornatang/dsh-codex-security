import { rename, symlink } from 'node:fs/promises'

const [directory, moved, replacement, mode] = process.argv.slice(2)
try {
  await rename(directory, moved)
  if (mode === 'directory') await rename(replacement, directory)
  else await symlink(replacement, directory, process.platform === 'win32' ? 'junction' : 'dir')
  process.stdout.write('swapped')
} catch (error) { process.stdout.write(String(error.code ?? error)) }
