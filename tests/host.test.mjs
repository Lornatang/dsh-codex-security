import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { Context } from '@deepseek-ai/cordis'
import { SkillRegistry } from '@deepseek-ai/dsh-skill'
import { ToolsService } from '@deepseek-ai/dsh-tools'
import { ToolExecutionPipeline, executeToolBatch } from '@deepseek-ai/dsh-tools/pipeline'
import plugin from '../lib/index.js'
import { SKILL_NAMES, TOOL_NAMES } from '../lib/constants.js'

test('real Cordis and DSH registries load and execute the packaged host plugin', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'dcs-host-'))
  const target = join(temp, 'repo')
  const root = new Context()
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), 'export const value = 1\n')
    for (const args of [['init', '-q'], ['add', '.'], ['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'initial']]) {
      execFileSync('git', args, { cwd: target, stdio: 'ignore' })
    }
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    await root.plugin(SkillRegistry)
    const fiber = await root.extend({ profileContext: { patchPath: join(temp, 'cordis.patch.yml') } }).plugin(plugin, { stateDir: join(temp, 'state') })
    const skills = root.get('skills')
    const tools = root.get('tools')
    for (const name of SKILL_NAMES) {
      const skill = await skills.get(name)
      assert.equal(skill?.source, 'bundled', name)
      assert.ok(skill.content.length > 100, name)
    }
    for (const name of TOOL_NAMES) assert.ok(tools.get(name), name)

    let pipeline
    await root.plugin({ name: 'test-pipeline', inject: ['tools'], apply(ctx) { pipeline = new ToolExecutionPipeline(ctx) } })
    async function call(name, args) {
      const output = await executeToolBatch({
        calls: [{ type: 'tool-call', id: 'call-' + name, name, arguments: JSON.stringify(args) }],
        signal: new AbortController().signal,
      }, pipeline, () => 1)
      return output.results[0].result
    }
    const inspected = await call('codex_security_inspect_target', { targetPath: target })
    assert.equal(inspected.isError, false, JSON.stringify(inspected))
    assert.equal(inspected.value.target.kind, 'git_worktree')
    assert.equal(Object.hasOwn(inspected.value.target, 'remote'), false)
    const invalid = await call('codex_security_inspect_target', { targetPath: target, unexpected: true })
    assert.equal(invalid.isError, true)
    assert.match(invalid.error.message, /invalid tool arguments/)
    const started = await call('codex_security_start_standard_scan', { targetPath: target })
    assert.equal(started.isError, false, JSON.stringify(started))
    assert.match(started.value.scanId, /^cs_[a-f0-9]{24}$/)

    await fiber.dispose()
    assert.equal(await skills.get('security-scan'), undefined)
    assert.equal(tools.get('codex_security_inspect_target'), undefined)
  } finally {
    await root.fiber.dispose()
    await rm(temp, { recursive: true, force: true })
  }
})
