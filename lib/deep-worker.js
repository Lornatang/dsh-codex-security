import { createHash } from 'node:crypto';
import { setImmediate as yieldEventLoop } from 'node:timers/promises';
import { digestWorkerSource, readWorkerSource, sourceRootIdentity, workerSourcePath } from './secure-read.js';
const TEXT_CACHE_ENTRIES = 8;
const TEXT_CACHE_BYTES = 4 * 1024 * 1024;
/** Compact adjacent chunks conservatively using their latest model step. */
export function mergeReceiptRanges(ranges, next) {
    const compare = (a, b) => (a?.turn ?? -1) - (b?.turn ?? -1) || (a?.step ?? -1) - (b?.step ?? -1);
    const sorted = [...ranges, next].sort((a, b) => a.start - b.start || b.end - a.end);
    const merged = [];
    for (const range of sorted) {
        const previous = merged[merged.length - 1];
        if (!previous || previous.total !== range.total || range.start > previous.end) {
            merged.push({ ...range });
            continue;
        }
        if (range.end <= previous.end && compare(previous.position, range.position) <= 0)
            continue;
        if (range.start <= previous.start && range.end >= previous.end && compare(range.position, previous.position) <= 0) {
            merged[merged.length - 1] = { ...range };
            continue;
        }
        previous.end = Math.max(previous.end, range.end);
        if (compare(previous.position, range.position) < 0)
            previous.position = range.position;
    }
    return merged;
}
/** Capture exact source bytes without allowing links or paths outside the target. */
export async function captureWorkerSnapshot(rootPath, paths, maxFileBytes, signal) {
    signal?.throwIfAborted();
    const root = sourceRootIdentity(rootPath);
    const files = Object.create(null);
    const observedDigests = Object.create(null);
    const unavailable = [];
    let visited = 0;
    for (const path of [...new Set(paths)].sort()) {
        if (++visited % 32 === 0)
            await yieldEventLoop();
        signal?.throwIfAborted();
        try {
            const content = readWorkerSource(root.path, path, maxFileBytes, root.identity);
            const digest = createHash('sha256').update(content).digest('hex');
            observedDigests[path] = digest;
            const text = content.toString('utf8');
            if (!Buffer.from(text, 'utf8').equals(content))
                throw new Error('worker source is not valid UTF-8');
            files[path] = { sha256: digest };
        }
        catch (error) {
            signal?.throwIfAborted();
            if (!Object.hasOwn(observedDigests, path)) {
                try {
                    observedDigests[path] = await digestWorkerSource(root.path, path, root.identity, signal);
                }
                catch {
                    signal?.throwIfAborted();
                }
            }
            unavailable.push({ path, reason: error instanceof Error ? error.message.slice(0, 1000) : 'worker source is unavailable' });
        }
    }
    return {
        rootPath: root.path, rootIdentity: { dev: String(root.identity.dev), ino: String(root.identity.ino) },
        maxFileBytes, files, unavailable, observedDigests,
    };
}
/** Verify that the secure per-file capture is exactly the target originally bound. */
export function assertWorkerSnapshotMatches(target, paths, snapshot) {
    if (target.kind === 'git_diff')
        throw new Error('codex-security: Deep worker snapshots do not support diffs');
    const hash = createHash('sha256');
    hash.update(JSON.stringify({ kind: target.kind, revision: target.revision ?? null, baseRevision: target.baseRevision ?? null, diffFiles: null }));
    for (const path of [...paths].sort()) {
        const digest = snapshot.observedDigests && Object.hasOwn(snapshot.observedDigests, path) ? snapshot.observedDigests[path] : 'unavailable';
        hash.update('\u0000' + path + '\u0000' + digest);
    }
    if ('codex-security-snapshot/v1:sha256:' + hash.digest('hex') !== target.snapshotDigest) {
        throw new Error('codex-security: secure worker snapshot differs from the originally bound target or contains an unverifiable file');
    }
}
/** Bind each worker to a fixed target and exact file digests. */
export class WorkerRegistry {
    workers = new Map();
    reserve(childId, snapshot, options = {}) {
        if (!childId || this.workers.has(childId))
            throw new Error('codex-security: invalid or duplicate worker binding');
        const root = sourceRootIdentity(snapshot.rootPath);
        if (snapshot.rootIdentity && (String(root.identity.dev) !== snapshot.rootIdentity.dev || String(root.identity.ino) !== snapshot.rootIdentity.ino))
            throw new Error('codex-security: worker target directory changed since snapshot');
        const files = Object.create(null);
        for (const [path, item] of Object.entries(snapshot.files)) {
            if (workerSourcePath(path) !== path || !/^[a-f0-9]{64}$/.test(item.sha256))
                throw new Error('codex-security: invalid worker inventory');
            files[path] = { sha256: item.sha256 };
        }
        if (!Number.isSafeInteger(snapshot.maxFileBytes) || snapshot.maxFileBytes < 1)
            throw new Error('codex-security: invalid worker size limit');
        this.workers.set(childId, { rootPath: root.path, rootNode: root.identity, maxFileBytes: snapshot.maxFileBytes, files, receipts: new Set(), ranges: new Map(), allowUnpositioned: options.allowUnpositionedReceipts === true, textCache: new Map() });
    }
    release(childId) { this.workers.delete(childId); }
    has(childId) { return this.workers.has(childId); }
    list(childId) { return Object.keys(this.binding(childId).files).sort(); }
    receipts(childId) {
        const binding = this.binding(childId);
        const complete = new Set(binding.receipts);
        for (const [path, chunks] of binding.ranges) {
            const eligible = chunks.filter((chunk) => chunk.position ? binding.finalStep &&
                (chunk.position.turn < binding.finalStep.turn || (chunk.position.turn === binding.finalStep.turn && chunk.position.step < binding.finalStep.step)) : binding.allowUnpositioned);
            const sorted = eligible.sort((a, b) => a.start - b.start);
            if (!sorted.length)
                continue;
            let covered = 0;
            for (const chunk of sorted) {
                if (chunk.start > covered)
                    break;
                covered = Math.max(covered, chunk.end);
            }
            if (covered === sorted[0].total && sorted[0].start === 0)
                complete.add(path);
        }
        return [...complete].sort();
    }
    acceptFinalStep(childId, position) {
        const binding = this.workers.get(childId);
        if (binding)
            binding.finalStep = position;
    }
    async read(childId, path) {
        return this.readText(childId, path);
    }
    readText(childId, path) {
        const binding = this.binding(childId);
        const source = workerSourcePath(path);
        if (!Object.hasOwn(binding.files, source))
            throw new Error('codex-security: worker source path is outside the bound inventory');
        const file = binding.files[source];
        const bytes = readWorkerSource(binding.rootPath, source, binding.maxFileBytes, binding.rootNode, file.sha256);
        const text = bytes.toString('utf8');
        if (!Buffer.from(text, 'utf8').equals(bytes))
            throw new Error('codex-security: worker source is not valid UTF-8');
        this.cacheText(binding, source, text);
        return text;
    }
    /** Reuse the bytes verified by the preceding read; fall back to a fresh verified read. */
    cachedText(childId, path) {
        const binding = this.binding(childId);
        const source = workerSourcePath(path);
        const cached = binding.textCache.get(source);
        return cached !== undefined ? cached : this.readText(childId, path);
    }
    /** Cache the verified text so chunk acceptance does not re-read whole files. */
    cacheText(binding, source, text) {
        binding.textCache.set(source, text);
        let bytes = 0;
        for (const value of binding.textCache.values())
            bytes += Buffer.byteLength(value, 'utf8');
        while (binding.textCache.size > TEXT_CACHE_ENTRIES || bytes > TEXT_CACHE_BYTES) {
            const oldest = binding.textCache.keys().next().value;
            if (oldest === undefined)
                break;
            bytes -= Buffer.byteLength(binding.textCache.get(oldest) ?? '', 'utf8');
            binding.textCache.delete(oldest);
        }
    }
    async readChunk(childId, path, offset) {
        if (!Number.isSafeInteger(offset) || offset < 0)
            throw new Error('codex-security: invalid worker source offset');
        // Chunks after the first were re-opening and re-hashing the whole file. The
        // cache only ever holds bytes verified against the bound snapshot hash, so
        // serving them cannot smuggle unverified content to the worker.
        const content = this.cachedText(childId, path);
        if (offset > content.length)
            throw new Error('codex-security: worker source offset exceeds file length');
        const end = Math.min(offset + 4096, content.length);
        return { path, content: content.slice(offset, end), offset, nextOffset: end === content.length ? null : end, totalLength: content.length };
    }
    /** Verify each delivered chunk against the snapshot before counting its covered range. */
    acceptChunk(childId, value, position) {
        const binding = this.workers.get(childId);
        if (!binding || !Object.hasOwn(binding.files, value.path) || !Number.isSafeInteger(value.offset) || !Number.isSafeInteger(value.totalLength))
            return;
        if (!position && !binding.allowUnpositioned)
            return;
        const end = value.offset + value.content.length;
        if (value.offset < 0 || end > value.totalLength || (value.nextOffset !== null && value.nextOffset !== end) || (value.nextOffset === null && end !== value.totalLength))
            return;
        const original = this.cachedText(childId, value.path);
        if (original.length !== value.totalLength || original.slice(value.offset, end) !== value.content)
            return;
        const ranges = mergeReceiptRanges(binding.ranges.get(value.path) ?? [], { start: value.offset, end, total: value.totalLength, ...(position ? { position } : {}) });
        if (ranges.length > 16384)
            return;
        binding.ranges.set(value.path, ranges);
    }
    /** Called only after the host accepts the tool's authoritative result. */
    acceptRead(childId, path, content) {
        const binding = this.workers.get(childId);
        if (!binding || !Object.hasOwn(binding.files, path))
            return;
        if (createHash('sha256').update(content, 'utf8').digest('hex') === binding.files[path].sha256)
            binding.receipts.add(path);
    }
    binding(childId) {
        const binding = this.workers.get(childId);
        if (!binding)
            throw new Error('codex-security: worker has no active binding');
        return binding;
    }
}
/** Install in the persistent worker preset, so resumed child sessions remain confined. */
export function installWorkerGuard(ctx) {
    const allowed = new Set(['codex_security_worker_read', 'codex_security_worker_list', 'structured_output']);
    return ctx.tools.guard((execution) => allowed.has(execution.name) ? undefined : 'codex-security: tool is not available to a security review worker');
}
/** Register worker-only tools; ordinary agents never receive them in their tool set. */
export function registerWorkerTools(ctx, registry) {
    const options = { when: ({ agent }) => typeof agent.id === 'string' && registry.has(agent.id) };
    const output = { schema: { type: 'object', additionalProperties: true }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] };
    const workerId = (exec) => {
        const id = exec.agent?.id;
        if (typeof id !== 'string' || !registry.has(id))
            throw new Error('codex-security: worker has no active binding');
        return id;
    };
    const disposers = [
        ctx.tools.register({
            name: 'codex_security_worker_list', description: 'List files in this worker’s bound review inventory.',
            parameters: { type: 'object', properties: {}, additionalProperties: false }, output, timeoutMs: 60000,
            execute: async (_args, exec) => ({ files: registry.list(workerId(exec)) }),
        }, options),
        ctx.tools.register({
            name: 'codex_security_worker_read', description: 'Read a verified source chunk; repeat with nextOffset until it is null.',
            parameters: { type: 'object', properties: { path: { type: 'string' }, offset: { type: 'integer' } }, required: ['path'], additionalProperties: false }, output, timeoutMs: 60000,
            execute: async (args, exec) => {
                if (!args || typeof args !== 'object' || Array.isArray(args) || typeof args.path !== 'string')
                    throw new Error('codex-security: worker source path is required');
                const path = args.path;
                const offset = args.offset ?? 0;
                if (typeof offset !== 'number')
                    throw new Error('codex-security: invalid worker source offset');
                return registry.readChunk(workerId(exec), path, offset);
            },
        }, options),
    ];
    const off = ctx.on('tools/result', (execution, result) => {
        if (result.isError || typeof execution.agent?.id !== 'string' || !registry.has(execution.agent.id))
            return;
        const events = execution.agent.session?.snapshotEvents?.() ?? [];
        const call = [...events].reverse().find((event) => event.type === 'tool/call' && event.data?.['callId'] === execution.callId && event.data?.['name'] === execution.name);
        const turn = call?.data?.['turn'];
        const step = call?.data?.['step'];
        const position = typeof turn === 'number' && Number.isSafeInteger(turn) && typeof step === 'number' && Number.isSafeInteger(step) ? { turn, step } : undefined;
        if (execution.name === 'structured_output') {
            if (position)
                registry.acceptFinalStep(execution.agent.id, position);
            return;
        }
        if (execution.name !== 'codex_security_worker_read')
            return;
        const args = execution.arguments;
        const value = result.value;
        if (typeof args?.path !== 'string' || value?.path !== args.path || typeof value.content !== 'string')
            return;
        // The canonical value can survive while a post-execute policy replaces or
        // truncates the actual model-facing content. Count only the delivered JSON.
        if (result.content?.length !== 1 || result.content[0]?.type !== 'text' || typeof result.content[0].text !== 'string')
            return;
        try {
            const delivered = JSON.parse(result.content[0].text);
            if (delivered?.path === value.path && delivered.content === value.content && delivered.offset === value.offset &&
                delivered.nextOffset === value.nextOffset && delivered.totalLength === value.totalLength &&
                typeof value.offset === 'number' && typeof value.totalLength === 'number' && (typeof value.nextOffset === 'number' || value.nextOffset === null)) {
                registry.acceptChunk(execution.agent.id, { path: args.path, content: value.content, offset: value.offset, nextOffset: value.nextOffset, totalLength: value.totalLength }, position);
            }
        }
        catch { /* A replaced, truncated or non-JSON projection is not a receipt. */ }
    });
    return () => { off?.(); for (const dispose of disposers)
        dispose(); };
}
