import { readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ensureDir, joinWithin, nowIso, readJson, readText, sanitizeRelative, writeFileAtomic, writeJsonAtomic, sha256 } from './util.js';
/** Files owned by the seal step; agents cannot overwrite them through save_artifact. */
const SEALED_FILES = new Set(['scan.json', 'findings.json', 'coverage.json', 'scan-manifest.json', 'sarif.json', 'report.md', 'threat-model.md']);
const INTERNAL_FILES = new Set([...SEALED_FILES, 'candidates.json', 'validations.json', 'attack-paths.json', 'review-items.json', 'triage.json']);
export function defaultStateDir(patchPath, configured) {
    if (configured.length > 0)
        return configured;
    if (patchPath && patchPath.length > 0)
        return join(dirname(patchPath), 'data', 'codex-security');
    const home = process.env['DSH_HOME'] || join(process.env['HOME'] ?? process.cwd(), '.dsh');
    return join(home, 'profiles', 'web', 'data', 'codex-security');
}
export function repoKeyFor(rootPath) {
    return sha256(rootPath).slice(0, 16);
}
function emptySeverityCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    return counts;
}
export function summarize(record) {
    return {
        scanId: record.scanId,
        mode: record.mode,
        status: record.status,
        repoKey: record.repoKey,
        target: {
            displayName: record.target.displayName,
            kind: record.target.kind,
            ...(record.target.revision ? { revision: record.target.revision } : {}),
            ...(record.target.baseRevision ? { baseRevision: record.target.baseRevision } : {}),
            ...(record.target.headRevision ? { headRevision: record.target.headRevision } : {}),
        },
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        findingsCount: record.findingsCount,
        severityCounts: record.severityCounts,
        progress: { phase: record.progress.phase, discoveryRuns: record.progress.discoveryRuns, updatedAt: record.progress.updatedAt },
        ...(record.policy ? { policy: record.policy } : {}),
    };
}
export class ScanStore {
    stateDir;
    indexCache;
    queue = Promise.resolve();
    constructor(stateDir) {
        this.stateDir = stateDir;
    }
    get indexPath() { return join(this.stateDir, 'index.json'); }
    scanDir(record) {
        return join(this.stateDir, 'repositories', record.repoKey, 'scans', record.scanId);
    }
    async init() {
        await ensureDir(this.stateDir);
        await ensureDir(join(this.stateDir, 'repositories'));
    }
    serialize(operation) {
        const next = this.queue.then(operation, operation);
        this.queue = next.catch(() => undefined);
        return next;
    }
    async loadIndex() {
        if (this.indexCache)
            return this.indexCache;
        const stored = await readJson(this.indexPath);
        this.indexCache = stored && stored.version === 1 ? stored : await this.rebuildIndex();
        return this.indexCache;
    }
    async rebuildIndex() {
        const index = { version: 1, scans: {} };
        const repos = await readdir(join(this.stateDir, 'repositories')).catch(() => []);
        for (const repoKey of repos) {
            const scansDir = join(this.stateDir, 'repositories', repoKey, 'scans');
            const scanIds = await readdir(scansDir).catch(() => []);
            for (const scanId of scanIds) {
                if (!/^cs_[a-f0-9]{24}$/.test(scanId))
                    continue;
                const record = await readJson(join(scansDir, scanId, 'scan.json'));
                if (record?.scanId === scanId && record.repoKey === repoKey)
                    index.scans[scanId] = { ...summarize(record), repoKey };
            }
        }
        return index;
    }
    async saveIndex(index) {
        this.indexCache = index;
        await writeJsonAtomic(this.indexPath, index);
    }
    async create(input) {
        return this.serialize(async () => {
            const timestamp = nowIso();
            const record = {
                scanId: input.scanId,
                repoKey: repoKeyFor(input.target.rootPath),
                mode: input.mode,
                status: 'running',
                promptOnly: input.promptOnly,
                createdAt: timestamp,
                updatedAt: timestamp,
                target: input.target,
                scope: input.scope,
                inventory: input.inventory,
                ...(input.diffFiles ? { diffFiles: input.diffFiles } : {}),
                progress: { phase: 'target-bound', notes: [], discoveryRuns: 0, startedAt: timestamp, updatedAt: timestamp },
                ...(input.budget ? { budget: input.budget } : {}),
                ...(input.notes ? { notes: input.notes } : {}),
                ...(input.threatModel ? { threatModel: input.threatModel } : {}),
                ...(input.previousScanId ? { previousScanId: input.previousScanId } : {}),
                artifacts: [],
                findingsCount: 0,
                severityCounts: emptySeverityCounts(),
                warnings: input.warnings,
            };
            await this.writeRecord(record);
            const dir = this.scanDir(record);
            await ensureDir(join(dir, 'checkpoints'));
            await ensureDir(join(dir, 'artifacts'));
            const index = await this.loadIndex();
            index.scans[record.scanId] = { ...summarize(record), repoKey: record.repoKey };
            await this.saveIndex(index);
            return record;
        });
    }
    async writeRecord(record) {
        await writeJsonAtomic(join(this.scanDir(record), 'scan.json'), record);
    }
    async get(scanId) {
        if (!/^cs_[a-f0-9]{24}$/.test(scanId))
            return undefined;
        const index = await this.loadIndex();
        const entry = index.scans[scanId];
        if (entry) {
            const dir = join(this.stateDir, 'repositories', entry.repoKey, 'scans', scanId);
            const record = await readJson(join(dir, 'scan.json'));
            if (record)
                return { record, dir };
        }
        // Fallback: index may be stale or missing; scan the repository directories.
        const reposDir = join(this.stateDir, 'repositories');
        let repos = [];
        try {
            repos = await readdir(reposDir);
        }
        catch {
            return undefined;
        }
        for (const repoKey of repos) {
            const dir = join(reposDir, repoKey, 'scans', scanId);
            const record = await readJson(join(dir, 'scan.json'));
            if (record) {
                index.scans[scanId] = { ...summarize(record), repoKey };
                await this.saveIndex(index);
                return { record, dir };
            }
        }
        return undefined;
    }
    async update(scanId, mutate) {
        return this.serialize(async () => {
            const found = await this.get(scanId);
            if (!found)
                throw new Error('codex-security: scan not found: ' + scanId);
            const record = found.record;
            mutate(record);
            record.updatedAt = nowIso();
            record.progress.updatedAt = record.updatedAt;
            await this.writeRecord(record);
            const index = await this.loadIndex();
            index.scans[record.scanId] = { ...summarize(record), repoKey: record.repoKey };
            await this.saveIndex(index);
            return record;
        });
    }
    async writeScanFile(scanId, name, value) {
        const found = await this.get(scanId);
        if (!found)
            throw new Error('codex-security: scan not found: ' + scanId);
        const target = joinWithin(found.dir, name);
        await writeJsonAtomic(target, value);
        return target;
    }
    async readScanFile(scanId, name) {
        const found = await this.get(scanId);
        if (!found)
            throw new Error('codex-security: scan not found: ' + scanId);
        return readJson(joinWithin(found.dir, name));
    }
    async list() {
        return this.serialize(async () => {
            const index = await this.rebuildIndex();
            await this.saveIndex(index);
            return Object.values(index.scans).sort((left, right) => right.createdAt.localeCompare(left.createdAt));
        });
    }
    async saveArtifact(scanId, relativePath, content, mediaType) {
        const found = await this.get(scanId);
        if (!found)
            throw new Error('codex-security: scan not found: ' + scanId);
        if (found.record.status !== 'running')
            throw new Error('codex-security: cannot change artifacts after scan is ' + found.record.status);
        const clean = sanitizeRelative(relativePath);
        if (INTERNAL_FILES.has(clean) || clean === 'checkpoints' || clean.startsWith('checkpoints/'))
            throw new Error('codex-security: cannot overwrite internal scan path: ' + clean);
        const target = joinWithin(found.dir, clean);
        const data = Buffer.from(content, 'utf8');
        await ensureDir(dirname(target));
        await writeFileAtomic(target, data);
        const digest = sha256(data);
        return { path: clean, bytes: data.byteLength, sha256: digest, mediaType };
    }
    async readArtifact(scanId, relativePath, limit) {
        const found = await this.get(scanId);
        if (!found)
            throw new Error('codex-security: scan not found: ' + scanId);
        const clean = sanitizeRelative(relativePath);
        const target = joinWithin(found.dir, clean);
        const content = await readText(target, limit);
        if (content === undefined)
            throw new Error('codex-security: artifact not found: ' + relativePath);
        const { stat } = await import('node:fs/promises');
        const info = await stat(target);
        return { path: clean, content, bytes: info.size, truncated: info.size > limit };
    }
    async listArtifacts(scanId) {
        const found = await this.get(scanId);
        if (!found)
            return [];
        const results = [];
        const walk = async (dir, relBase) => {
            let entries;
            try {
                entries = await readdir(dir, { withFileTypes: true });
            }
            catch {
                return;
            }
            for (const entry of entries) {
                const rel = relBase.length > 0 ? relBase + '/' + entry.name : entry.name;
                if (entry.isDirectory()) {
                    if (relBase.length === 0 && entry.name === 'checkpoints')
                        continue;
                    await walk(join(dir, entry.name), rel);
                    continue;
                }
                if (!entry.isFile())
                    continue;
                if (relBase.length === 0 && SEALED_FILES.has(entry.name))
                    continue;
                const { stat } = await import('node:fs/promises');
                const info = await stat(join(dir, entry.name));
                results.push({ path: rel, bytes: info.size });
            }
        };
        await walk(found.dir, '');
        return results.sort((left, right) => left.path.localeCompare(right.path));
    }
    async readTriage(scanId) {
        return (await this.readScanFile(scanId, 'triage.json')) ?? {};
    }
    async setTriage(scanId, entry) {
        return this.serialize(async () => {
            const found = await this.get(scanId);
            if (!found)
                throw new Error('codex-security: scan not found: ' + scanId);
            const triage = (await readJson(join(found.dir, 'triage.json'))) ?? {};
            triage[entry.findingId] = entry;
            await writeJsonAtomic(join(found.dir, 'triage.json'), triage);
            return entry;
        });
    }
    async readFindings(scanId) {
        const document = await this.readScanFile(scanId, 'findings.json');
        return document?.findings ?? [];
    }
}
