import { rename, symlink } from 'node:fs/promises'

const [directory, moved, replacement, mode] = process.argv.slice(2)
try {
  if (mode === 'link-only') {
    await symlink(replacement, directory, process.platform === 'win32' ? 'junction' : 'dir')
    process.stdout.write('swapped')
    process.exit(0)
  }
  await rename(directory, moved)
  if (mode === 'roundtrip') await rename(moved, directory)
  else if (mode === 'directory') await rename(replacement, directory)
  else if (mode !== 'move-only') await symlink(replacement, directory, process.platform === 'win32' ? 'junction' : 'dir')
  process.stdout.write('swapped')
} catch (error) { process.stdout.write(String(error.code ?? error)) }
