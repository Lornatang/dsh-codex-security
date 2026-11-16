import type { DeepActivation, DeepHost } from './deep-coordinator.js'

const WORKER_PRESET = 'codex-security-deep-worker-v1'

interface Provider {
  inheritsParentContext: boolean
  prepareContinuable?: unknown
  capabilities: { agentPreset?: boolean; outputSchema?: boolean; depthLimit?: boolean }
}
export interface DshSubagents {
  getProvider(name: string): Provider | undefined
  startActivation(spec: Record<string, unknown>): Promise<DeepActivation>
}
export interface DshPresets {
  register(definition: Record<string, unknown>): Promise<() => Promise<void>>
  resolve(id: string): Promise<{ id: string; broken?: string }>
}

/** Use only DSH's local, fresh-context activation with a persistent restricted preset. */
export class DshWorkerHost implements DeepHost {
  private registration?: Promise<() => Promise<void>>
  constructor(private readonly subagents: DshSubagents, private readonly presets: DshPresets) {}

  async ensureReady(): Promise<void> {
    const provider = this.subagents.getProvider('spawn')
    if (!provider || provider.inheritsParentContext || typeof provider.prepareContinuable !== 'function' ||
        !provider.capabilities.agentPreset || !provider.capabilities.outputSchema || !provider.capabilities.depthLimit) {
      throw new Error('codex-security: an isolated local spawn provider with preset and structured-output support is required')
    }
    this.registration ??= this.presets.register({ id: WORKER_PRESET, name: 'Codex Security Deep worker', plugins: [
      { name: '@deepseek-ai/dsh-tool-executor-native' },
      { name: '@lornatang/dsh-codex-security/worker-preset' },
    ] })
    await this.registration
    const preset = await this.presets.resolve(WORKER_PRESET)
    if (preset.broken) throw new Error('codex-security: isolated worker preset is unavailable: ' + preset.broken)
  }

  async start(request: Parameters<DeepHost['start']>[0]): Promise<DeepActivation> {
    await this.ensureReady()
    return this.subagents.startActivation({
      provider: 'spawn', parent: request.agent, childId: request.childId, signal: request.signal,
      prompt: [{ type: 'text', text: request.prompt }], outputSchema: request.outputSchema,
      label: 'Security review worker', delivery: 'caller', agentPreset: WORKER_PRESET,
    })
  }

  async dispose(): Promise<void> { if (this.registration) await (await this.registration)() }
}
