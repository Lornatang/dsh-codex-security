import { installWorkerGuard } from './deep-worker.js'

export const name = 'codex-security-worker-preset'
export const inject = ['tools']

interface WorkerPresetContext {
  tools: { guard(callback: (execution: { name: string }) => string | undefined): () => void }
  effect(callback: () => () => void, label?: string): () => void
}

/** A worker's own preset retains this guard on cold resume. */
export function apply(ctx: WorkerPresetContext): void {
  ctx.effect(() => installWorkerGuard(ctx), 'codex-security: worker guard')
}

export default { name, inject, apply }
