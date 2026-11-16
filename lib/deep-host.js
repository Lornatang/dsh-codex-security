const WORKER_PRESET = 'codex-security-deep-worker-v1';
/** Use only DSH's local, fresh-context activation with a persistent restricted preset. */
export class DshWorkerHost {
    subagents;
    presets;
    registration;
    constructor(subagents, presets) {
        this.subagents = subagents;
        this.presets = presets;
    }
    async ensureReady() {
        const provider = this.subagents.getProvider('spawn');
        if (!provider || provider.inheritsParentContext || typeof provider.prepareContinuable !== 'function' ||
            !provider.capabilities.agentPreset || !provider.capabilities.outputSchema || !provider.capabilities.depthLimit) {
            throw new Error('codex-security: an isolated local spawn provider with preset and structured-output support is required');
        }
        this.registration ??= this.presets.register({ id: WORKER_PRESET, name: 'Codex Security Deep worker', plugins: [
                { name: '@deepseek-ai/dsh-tool-executor-native' },
                { name: '@lornatang/dsh-codex-security/worker-preset' },
            ] });
        await this.registration;
        const preset = await this.presets.resolve(WORKER_PRESET);
        if (preset.broken)
            throw new Error('codex-security: isolated worker preset is unavailable: ' + preset.broken);
    }
    async start(request) {
        await this.ensureReady();
        return this.subagents.startActivation({
            provider: 'spawn', parent: request.agent, childId: request.childId, signal: request.signal,
            prompt: [{ type: 'text', text: request.prompt }], outputSchema: request.outputSchema,
            label: 'Security review worker', delivery: 'caller', agentPreset: WORKER_PRESET,
        });
    }
    async dispose() { if (this.registration)
        await (await this.registration)(); }
}
