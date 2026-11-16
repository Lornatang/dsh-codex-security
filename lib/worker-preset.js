import { installWorkerGuard } from './deep-worker.js';
export const name = 'codex-security-worker-preset';
export const inject = ['tools'];
/** A worker's own preset retains this guard on cold resume. */
export function apply(ctx) {
    ctx.effect(() => installWorkerGuard(ctx), 'codex-security: worker guard');
}
export default { name, inject, apply };
