import { DISPOSITIONS, SEVERITIES, SEVERITY_SCORE } from './types.js';
import { compareSeverity, normalizeLine, sanitizeRelative, sha256, slugify, stableTargetId } from './util.js';
import { VERSION } from './constants.js';
const SEVERITY_SET = new Set(SEVERITIES);
const CONFIDENCE_SET = new Set(['high', 'medium', 'low']);
const DISPOSITION_SET = new Set(DISPOSITIONS);
export function normalizeRuleId(value) {
    const normalized = String(value ?? '').toLowerCase().replace(/[^a-z0-9._/-]+/g, '-').replace(/^[^a-z0-9]+/, '').replace(/\/+$/, '');
    return normalized.length > 0 ? normalized.slice(0, 96) : 'code-security.finding';
}
export function normalizeAnchor(ruleId, path, lineText, instance) {
    const rulePart = normalizeRuleId(ruleId).replace(/[^a-z0-9._-]/g, '-');
    const pathPart = slugify(path, 40).toLowerCase().replace(/[^a-z0-9._-]/g, '-');
    const evidence = normalizeLine(lineText ?? '');
    const evidencePart = evidence.length > 0 ? sha256(evidence).slice(0, 12) : (instance ? sha256(instance).slice(0, 12) : 'anchor');
    const compactRule = rulePart.length > 0 ? rulePart : 'rule';
    const value = compactRule + '/' + (pathPart.length > 0 ? pathPart : 'file') + '/' + evidencePart;
    return value.slice(0, 200);
}
export function fingerprintFor(targetId, ruleId, anchor, instance) {
    return 'codex-security/v1:sha256:' + sha256(['codex-security/v1', targetId, ruleId, anchor, instance ?? ''].join('\u0000'));
}
export function idsFor(scanId, targetId, ruleId, anchor, instance) {
    const primary = fingerprintFor(targetId, ruleId, anchor, instance);
    return {
        primary,
        findingId: 'csf_' + sha256(primary).slice(0, 24),
        occurrenceId: 'occ_' + sha256(scanId + '\u0000' + primary).slice(0, 24),
    };
}
export function normalizeSeverity(input) {
    const level = String(input?.level ?? '').toLowerCase();
    if (!SEVERITY_SET.has(level))
        throw new Error('codex-security: severity.level must be one of ' + SEVERITIES.join(', '));
    if (input.score !== undefined && (typeof input.score !== 'number' || !Number.isFinite(input.score) || input.score < 0 || input.score > 10))
        throw new Error('codex-security: severity.score must be a number between 0 and 10');
    const score = input.score ?? SEVERITY_SCORE[level];
    return {
        ...input,
        level,
        score,
        ...(input.rationale ? { rationale: String(input.rationale) } : {}),
        scoringSystem: input.scoringSystem ? String(input.scoringSystem) : (input.score === undefined ? 'dsh-severity/v1' : 'unspecified'),
        ...(input.changeConditions ? { changeConditions: String(input.changeConditions) } : {}),
    };
}
export function normalizeConfidence(input) {
    const level = String(input?.level ?? '').toLowerCase();
    if (!CONFIDENCE_SET.has(level))
        throw new Error('codex-security: confidence.level must be high, medium or low');
    const rationale = String(input.rationale ?? '').trim().slice(0, 4000);
    if (!rationale)
        throw new Error('codex-security: confidence.rationale is required');
    return { ...input, level, rationale };
}
export function normalizeLocation(input) {
    const path = sanitizeRelative(input.path);
    const startLine = Number(input.startLine);
    if (!Number.isInteger(startLine) || startLine < 1)
        throw new Error('codex-security: locations[].startLine must be a positive integer');
    const endLine = input.endLine === undefined ? undefined : Number(input.endLine);
    if (endLine !== undefined && (!Number.isInteger(endLine) || endLine < startLine))
        throw new Error('codex-security: locations[].endLine must be >= startLine');
    return { ...input, path, startLine, ...(endLine === undefined ? {} : { endLine }), ...(input.role ? { role: String(input.role) } : {}) };
}
export function normalizeFinding(scanId, input, options) {
    if (!input || typeof input !== 'object')
        throw new Error('codex-security: each finding must be an object');
    if (typeof input.ruleId !== 'string' || !input.ruleId.trim())
        throw new Error('codex-security: finding.ruleId is required');
    const ruleId = normalizeRuleId(input.ruleId ?? '');
    const title = typeof input.title === 'string' ? input.title.trim() : '';
    const summary = typeof input.summary === 'string' ? input.summary.trim() : '';
    if (title.length === 0)
        throw new Error('codex-security: finding.title is required');
    if (summary.length === 0)
        throw new Error('codex-security: finding.summary is required');
    if (!Array.isArray(input.locations) || input.locations.length === 0)
        throw new Error('codex-security: finding.locations must contain at least one location for ' + title);
    const locations = input.locations.map((location) => normalizeLocation(location));
    const remediation = typeof input.remediation === 'string' ? input.remediation.trim() : '';
    if (remediation.length === 0)
        throw new Error('codex-security: finding.remediation is required for ' + title);
    const first = locations[0];
    const evidenceKey = first.path + ':' + first.startLine;
    const lineText = options.evidenceLines?.get(evidenceKey);
    if (input.identity && ((input.anchor !== undefined && input.anchor !== input.identity.anchor) || (input.instance !== undefined && input.instance !== input.identity.instance)))
        throw new Error('codex-security: conflicting finding identity');
    const specifiedAnchor = input.identity?.anchor ?? input.anchor;
    const instance = input.identity?.instance ?? input.instance;
    const slug = /^[a-z0-9][a-z0-9._/-]*$/;
    if (specifiedAnchor !== undefined && !slug.test(specifiedAnchor))
        throw new Error('codex-security: finding identity anchor must be a lowercase semantic slug');
    if (instance !== undefined && !slug.test(instance))
        throw new Error('codex-security: finding identity instance must be a lowercase semantic slug');
    const anchor = specifiedAnchor ?? normalizeAnchor(ruleId, first.path, lineText, instance);
    const ids = idsFor(scanId, options.targetId ?? stableTargetId(options.rootPath), ruleId, anchor, instance);
    const severity = normalizeSeverity(input.severity);
    const confidence = normalizeConfidence(input.confidence);
    const taxonomy = input.taxonomy ?? { category: 'other' };
    if (typeof taxonomy.category !== 'string' || !taxonomy.category.trim())
        throw new Error('codex-security: taxonomy.category must be a non-empty string');
    const category = taxonomy.category.trim();
    const cwe = taxonomy.cwe === undefined ? [] : (Array.isArray(taxonomy.cwe) ? taxonomy.cwe : [taxonomy.cwe]);
    if (cwe.some((value) => typeof value !== 'string' || !value))
        throw new Error('codex-security: taxonomy.cwe must contain non-empty strings');
    const { writeup, ...findingInput } = input;
    if (writeup && (typeof writeup.reportPath !== 'string' || !writeup.reportPath.trim()))
        throw new Error('codex-security: finding writeup.reportPath is required');
    const finding = {
        ...findingInput,
        findingId: ids.findingId,
        occurrenceId: ids.occurrenceId,
        ruleId,
        identity: { anchor, ...(instance ? { instance } : {}) },
        fingerprints: { algorithm: 'codex-security/v1', primary: ids.primary },
        title: title.slice(0, 300),
        summary: summary.slice(0, 8000),
        severity,
        confidence,
        taxonomy: { ...taxonomy, category, cwe },
        locations,
        remediation: remediation.slice(0, 8000),
        ...(input.codeEvidence ? { codeEvidence: input.codeEvidence } : {}),
        ...(input.validation ? { validation: input.validation } : {}),
        ...(input.attackPath ? { attackPath: input.attackPath } : {}),
        ...(input.remediationTests ? { remediationTests: input.remediationTests } : {}),
        ...(input.preventiveControls ? { preventiveControls: input.preventiveControls } : {}),
        ...(writeup?.reportPath ? { writeup: { ...writeup, reportPath: sanitizeRelative(writeup.reportPath) } } : {}),
        provenance: { ...input.provenance, source: String(input.provenance?.source ?? 'agent-review') },
        ...(input.extensions ? { extensions: input.extensions } : {}),
        scanId,
    };
    return finding;
}
/** Verify the evidence links which JSON Schema alone cannot express. */
export function validateFindingEvidence(findings) {
    for (const finding of findings) {
        const ids = new Set();
        for (const key of ['codeEvidence', 'code_evidence']) {
            const list = finding[key];
            if (list === undefined || list === null)
                continue;
            if (!Array.isArray(list))
                throw new Error('codex-security: finding ' + key + ' must be an array');
            for (const value of list) {
                if (!value || typeof value !== 'object' || Array.isArray(value))
                    throw new Error('codex-security: code evidence must be an object');
                const evidence = value;
                if (typeof evidence['id'] !== 'string' || !evidence['id'] || typeof evidence['code'] !== 'string' || !evidence['code'] || ids.has(evidence['id']))
                    throw new Error('codex-security: code evidence needs a unique ID and code');
                ids.add(evidence['id']);
            }
        }
        const attack = finding.attackPath;
        const sections = [finding.rootCause, finding.root_cause, finding.validation, attack, attack?.['dataFlow'], attack?.['data_flow'], attack?.['dataflow'], attack?.['reachability']];
        for (const section of sections) {
            if (!section || typeof section !== 'object' || Array.isArray(section))
                continue;
            for (const key of ['evidenceRefs', 'evidence_refs']) {
                const refs = section[key];
                if (refs !== undefined && (!Array.isArray(refs) || refs.some((ref) => typeof ref !== 'string' || !ids.has(ref))))
                    throw new Error('codex-security: finding references unknown code evidence');
            }
        }
    }
}
export function validateDraft(input) {
    if (!input || typeof input !== 'object')
        throw new Error('codex-security: draft must be an object');
    const raw = input;
    if (raw.reviewState && raw.coverage && JSON.stringify(raw.reviewState) !== JSON.stringify(raw.coverage))
        throw new Error('codex-security: conflicting coverage and reviewState');
    const draft = { ...raw, reviewState: raw.reviewState ?? raw.coverage };
    if (!Array.isArray(draft.findings))
        throw new Error('codex-security: draft.findings must be an array');
    const reviewState = (draft.reviewState ?? {});
    if (!Array.isArray(reviewState.surfaces))
        throw new Error('codex-security: draft.reviewState.surfaces must be an array');
    if (reviewState.completeness !== undefined && !['complete', 'partial', 'unknown'].includes(reviewState.completeness))
        throw new Error('codex-security: invalid coverage completeness');
    const ids = new Set();
    for (const surface of reviewState.surfaces) {
        if (!surface || typeof surface.label !== 'string' || surface.label.trim().length === 0)
            throw new Error('codex-security: each coverage surface needs a non-empty label');
        if (!DISPOSITION_SET.has(String(surface.disposition)))
            throw new Error('codex-security: surface disposition must be one of ' + DISPOSITIONS.join(', '));
        if (surface.id !== undefined) {
            if (!surface.id || ids.has(surface.id))
                throw new Error('codex-security: coverage surface IDs must be non-empty and unique');
            ids.add(surface.id);
        }
        if (surface.receiptRefs !== undefined) {
            if (!Array.isArray(surface.receiptRefs))
                throw new Error('codex-security: surface.receiptRefs must be an array');
            for (const ref of surface.receiptRefs) {
                const value = String(ref);
                if (!value.startsWith('artifacts/') || value !== sanitizeRelative(value) || value.includes('\\'))
                    throw new Error('codex-security: surface receiptRefs must point under artifacts/: ' + value);
            }
        }
    }
    if (reviewState.explicitExclusions !== undefined && !Array.isArray(reviewState.explicitExclusions))
        throw new Error('codex-security: reviewState.explicitExclusions must be an array');
    if (reviewState.deferred !== undefined) {
        if (!Array.isArray(reviewState.deferred))
            throw new Error('codex-security: reviewState.deferred must be an array');
        const deferredIds = new Set();
        for (const entry of reviewState.deferred) {
            if (!entry || typeof entry.id !== 'string' || entry.id.trim().length === 0)
                throw new Error('codex-security: each deferred entry needs a non-empty id');
            if (deferredIds.has(entry.id))
                throw new Error('codex-security: reviewState.deferred ids must be unique');
            deferredIds.add(entry.id);
        }
    }
    return draft;
}
export function buildFindingsDocument(scanId, findings) {
    return { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId, generatedAt: new Date().toISOString(), findings };
}
export function severityCounts(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const finding of findings)
        counts[finding.severity.level] = (counts[finding.severity.level] ?? 0) + 1;
    return counts;
}
export function sortedFindings(findings) {
    return [...findings].sort((left, right) => compareSeverity(left.severity.level, right.severity.level) || left.title.localeCompare(right.title));
}
export function buildCoverage(scan, reviewState, modeOverride) {
    const mode = modeOverride ?? coverageMode(scan);
    const surfaces = sanitizeSurfaces(reviewState.surfaces);
    if (new Set(surfaces.map((surface) => surface.id)).size !== surfaces.length)
        throw new Error('codex-security: coverage surface IDs must be unique');
    const incomplete = (reviewState.deferred?.length ?? 0) > 0 || surfaces.some((surface) => surface.disposition === 'needs_follow_up') || scan.inventory.truncated || scan.warnings.some((warning) => warning.startsWith('snapshot could not hash file:') || warning.startsWith('inventory omitted symbolic link:'));
    if (reviewState.completeness === 'complete' && incomplete)
        throw new Error('codex-security: complete coverage cannot have deferred or incomplete work');
    const completeness = reviewState.completeness ?? (incomplete ? 'partial' : 'complete');
    const active = new Set((reviewState.deferred ?? []).map((entry) => entry.id));
    const resolved = new Set();
    for (const entry of reviewState.resolvedDeferred ?? []) {
        if (!entry.id || !entry.reason || active.has(entry.id) || resolved.has(entry.id))
            throw new Error('codex-security: invalid or duplicate resolved deferred work');
        resolved.add(entry.id);
    }
    return {
        ...reviewState,
        documentType: 'codex-security.coverage',
        schemaVersion: '1.0',
        scanId: scan.scanId,
        mode,
        completeness,
        inventoryStrategy: scan.target.kind === 'git_diff' ? 'diff' : scan.target.kind === 'directory_snapshot' ? 'directory' : scan.scope.includePaths.includes('.') ? 'repository' : 'scoped_path',
        includePaths: scan.scope.includePaths,
        excludePaths: scan.scope.excludePaths,
        surfaces,
        explicitExclusions: (reviewState.explicitExclusions ?? []).map((entry) => ({ ...entry, pattern: String(entry.pattern), reason: String(entry.reason) })),
        deferred: (reviewState.deferred ?? []).map((entry) => ({ ...entry, id: String(entry.id), reason: String(entry.reason), ...(entry.paths ? { paths: entry.paths } : {}), ...(entry.surfaceIds ? { surfaceIds: entry.surfaceIds } : {}) })),
        ...(reviewState.resolvedDeferred ? { resolvedDeferred: reviewState.resolvedDeferred } : {}),
        ...(reviewState.openQuestions ? { openQuestions: reviewState.openQuestions } : {}),
    };
}
function sanitizeSurfaces(surfaces) {
    return surfaces.map((surface, index) => {
        const disposition = String(surface.disposition);
        if (!DISPOSITION_SET.has(disposition))
            throw new Error('codex-security: invalid surface disposition ' + disposition);
        return {
            ...surface,
            id: String(surface.id ?? 'surface-' + (index + 1)),
            label: String(surface.label),
            disposition,
            receiptRefs: Array.isArray(surface.receiptRefs) ? surface.receiptRefs.map(String) : [],
            ...(surface.riskArea ? { riskArea: String(surface.riskArea) } : {}),
            ...(surface.notes ? { notes: String(surface.notes) } : {}),
        };
    });
}
function coverageMode(scan) {
    if (scan.mode === 'deep')
        return 'deep_repository';
    const kind = scan.target.kind;
    if (kind === 'git_diff')
        return scan.target.workingTree ? 'working_tree' : scan.target.baseRevision ? 'branch_diff' : 'diff';
    if (kind === 'directory_snapshot')
        return scan.scope.includePaths.includes('.') ? 'repository' : 'scoped_path';
    if (kind === 'git_worktree')
        return scan.scope.includePaths.includes('.') ? 'repository' : 'scoped_path';
    return 'repository';
}
export function policyGate(findings, threshold) {
    if (threshold === 'off')
        return { threshold, status: 'pass', failing: 0 };
    const rank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    const limit = rank[threshold];
    if (limit === undefined)
        return { threshold, status: 'pass', failing: 0 };
    const failing = findings.filter((finding) => (rank[finding.severity.level] ?? 9) <= limit).length;
    return { threshold, status: failing > 0 ? 'fail' : 'pass', failing };
}
export function renderReport(scan, findings, coverage, options) {
    const counts = severityCounts(findings);
    const lines = [];
    const push = (value = '') => { lines.push(value); };
    push('# Security review: ' + scan.target.displayName);
    push();
    push('| Field | Value |');
    push('| --- | --- |');
    push('| Scan | ' + scan.scanId + ' |');
    push('| Mode | ' + scan.mode + ' |');
    push('| Status | completed |');
    push('| Sealed | ' + options.sealedAt + ' |');
    push('| Target | ' + scan.target.kind + ' |');
    push('| Revision | ' + (scan.target.revision ?? '(no git revision)') + ' |');
    if (scan.target.baseRevision)
        push('| Base revision | ' + scan.target.baseRevision + ' |');
    if (scan.target.remote)
        push('| Remote | ' + scan.target.remote + ' |');
    push('| Snapshot | ' + scan.target.snapshotDigest + ' |');
    push('| Scope | ' + scan.scope.includePaths.join(', ') + ' |');
    push('| Excluded | ' + (scan.scope.excludePaths.length > 0 ? scan.scope.excludePaths.join(', ') : '(none beyond defaults)') + ' |');
    push('| Files inventoried | ' + scan.inventory.inspectedFiles + ' |');
    push('| Coverage completeness | ' + (coverage.completeness ?? 'unknown') + ' |');
    push();
    push('## Executive summary');
    push();
    push('| Severity | Count |');
    push('| --- | --- |');
    for (const level of SEVERITIES)
        push('| ' + level + ' | ' + counts[level] + ' |');
    push('| **Total** | **' + findings.length + '** |');
    push();
    push('| Coverage disposition | Surfaces |');
    push('| --- | --- |');
    const dispositionCounts = new Map();
    for (const surface of coverage.surfaces)
        dispositionCounts.set(surface.disposition, (dispositionCounts.get(surface.disposition) ?? 0) + 1);
    for (const [disposition, count] of dispositionCounts)
        push('| ' + disposition + ' | ' + count + ' |');
    push();
    push('## Findings');
    push();
    if (findings.length === 0) {
        push('No reportable findings. Static review cannot prove the absence of vulnerabilities; see coverage and limitations.');
        push();
    }
    const ordered = sortedFindings(findings);
    ordered.forEach((finding, index) => {
        push('### ' + (index + 1) + '. [' + finding.severity.level.toUpperCase() + '] ' + finding.title);
        push();
        push('- Finding: ' + finding.findingId + ' (occurrence ' + finding.occurrenceId + ')');
        push('- Rule: ' + finding.ruleId + ' | Category: ' + finding.taxonomy.category + (finding.taxonomy.cwe ? ' | CWE: ' + String(finding.taxonomy.cwe) : ''));
        push('- Severity: ' + finding.severity.level + ' (' + finding.severity.score + '/10)' + (finding.severity.rationale ? ' - ' + finding.severity.rationale : ''));
        push('- Confidence: ' + finding.confidence.level + (finding.confidence.rationale ? ' - ' + finding.confidence.rationale : ''));
        for (const location of finding.locations) {
            push('- Location: ' + location.path + ':' + location.startLine + (location.endLine ? '-' + location.endLine : '') + (location.role ? ' (' + location.role + ')' : ''));
        }
        push();
        push(finding.summary);
        push();
        if (finding.rootCause) {
            push('**Root cause:** ' + (typeof finding.rootCause === 'string' ? finding.rootCause : String(finding.rootCause['summary'] ?? JSON.stringify(finding.rootCause))));
            push();
        }
        if (finding.validation) {
            const validation = finding.validation;
            push('**Validation:** ' + (validation.status ?? validation.method ?? 'recorded') + (validation.summary ? ' - ' + validation.summary : ''));
            push();
        }
        if (finding.attackPath) {
            const attackPath = finding.attackPath;
            push('**Attack path:** ' + (attackPath.summary ?? 'See validation evidence'));
            if (Array.isArray(attackPath.steps) && attackPath.steps.length > 0) {
                for (const step of attackPath.steps)
                    push('1. ' + String(step));
            }
            push();
        }
        push('**Remediation:** ' + finding.remediation);
        push();
        if (finding.writeup?.reportPath) {
            push('Writeup: ' + finding.writeup.reportPath);
            push();
        }
    });
    push('## Coverage');
    push();
    if (coverage.surfaces.length === 0)
        push('No coverage surfaces were recorded.');
    else {
        push('| Surface | Disposition | Risk area | Receipts |');
        push('| --- | --- | --- | --- |');
        for (const surface of coverage.surfaces)
            push('| ' + surface.label + ' | ' + surface.disposition + ' | ' + (surface.riskArea ?? '') + ' | ' + surface.receiptRefs.join(', ') + ' |');
    }
    push();
    if (coverage.explicitExclusions.length > 0) {
        push('## Explicit exclusions');
        push();
        for (const exclusion of coverage.explicitExclusions)
            push('- ' + exclusion.pattern + ': ' + exclusion.reason);
        push();
    }
    if (coverage.deferred.length > 0) {
        push('## Deferred work');
        push();
        for (const deferred of coverage.deferred)
            push('- ' + deferred.id + ': ' + deferred.reason);
        push();
    }
    if (coverage.openQuestions && coverage.openQuestions.length > 0) {
        push('## Open questions');
        push();
        for (const question of coverage.openQuestions)
            push('- ' + question.question);
        push();
    }
    if (options.threatModel) {
        push('## Threat model');
        push();
        const model = options.threatModel;
        push(typeof model === 'string' ? model : JSON.stringify(model, null, 2));
        push();
    }
    push('## Limitations');
    push();
    push('- The host records an agent review and does not itself execute the target. Check the submitted validation evidence for any tests or dynamic analysis.');
    push('- Findings without validation evidence remain candidate risk, not confirmed exploitable behavior.');
    push('- Review depth is bounded by the recorded coverage surfaces, exclusions and deferred items.');
    push('- Target repository content must be treated as untrusted data; this report does not independently verify agent behavior.');
    push();
    return lines.join('\n');
}
export function toSarif(scan, findings) {
    const rules = new Map();
    for (const finding of findings) {
        if (!rules.has(finding.ruleId)) {
            rules.set(finding.ruleId, {
                id: finding.ruleId,
                name: finding.ruleId,
                shortDescription: { text: finding.taxonomy.category },
                properties: { category: finding.taxonomy.category, ...(finding.taxonomy.cwe ? { cwe: finding.taxonomy.cwe } : {}) },
            });
        }
    }
    const ruleList = [...rules.values()];
    const ruleIndex = new Map(ruleList.map((rule, index) => [rule.id, index]));
    const results = sortedFindings(findings).map((finding) => {
        const location = finding.locations[0];
        return {
            ruleId: finding.ruleId,
            ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
            level: sarifLevel(finding.severity.level),
            message: { text: finding.title + ': ' + finding.summary },
            locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: location.path, uriBaseId: '%SRCROOT%' },
                        region: { startLine: location.startLine, ...(location.endLine ? { endLine: location.endLine } : {}) },
                    },
                }],
            fingerprints: { 'codex-security/v1': finding.fingerprints.primary, findingId: finding.findingId },
            properties: { 'security-severity': finding.severity.score.toFixed(1), confidence: finding.confidence.level, category: finding.taxonomy.category, ...(finding.taxonomy.cwe ? { cwe: finding.taxonomy.cwe } : {}) },
        };
    });
    return {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [{
                tool: {
                    driver: {
                        name: 'codex-security',
                        semanticVersion: VERSION,
                        informationUri: 'https://github.com/Lornatang/dsh-codex-security',
                        rules: ruleList,
                    },
                },
                originalUriBaseIds: { '%SRCROOT%': { uri: pathToUri(scan.target.rootPath) } },
                results,
            }],
    };
}
function sarifLevel(level) {
    if (level === 'critical' || level === 'high')
        return 'error';
    if (level === 'medium')
        return 'warning';
    return 'note';
}
function pathToUri(path) {
    const normalized = path.split('\\').join('/');
    if (/^[A-Za-z]:\//.test(normalized))
        return 'file:///' + normalized;
    return 'file://' + normalized;
}
export function toCsv(findings) {
    const header = ['finding_id', 'occurrence_id', 'severity', 'confidence', 'rule_id', 'title', 'path', 'start_line', 'end_line', 'category', 'cwe', 'remediation'];
    const rows = sortedFindings(findings).map((finding) => {
        const location = finding.locations[0];
        return [finding.findingId, finding.occurrenceId, finding.severity.level, finding.confidence.level, finding.ruleId, finding.title, location.path, String(location.startLine), location.endLine ? String(location.endLine) : '', finding.taxonomy.category, finding.taxonomy.cwe ? String(finding.taxonomy.cwe) : '', finding.remediation];
    });
    const escape = (value) => /[",\n\r]/.test(value) ? '"' + value.split('"').join('""') + '"' : value;
    return [header, ...rows].map((row) => row.map((value) => escape(String(value))).join(',')).join('\n') + '\n';
}
export function findingStatusOf(entry) {
    return entry?.status ?? 'open';
}
