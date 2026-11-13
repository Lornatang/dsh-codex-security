window.__ModuleLoader__.load({id:"dsh-codex-security",factory:(require)=>{
var module={exports:{}};var exports=module.exports;
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.inject = exports.name = void 0;
exports.apply = apply;
const jsx_runtime_1 = require("react/jsx-runtime");
/**
 * Codex Security workbench — browser half of dsh-codex-security.
 *
 * Registers one settings.section that renders the scan workbench against the
 * plugin's HTTP routes (/plugins/codex-security). Every response path guards
 * HTTP failures and non-JSON bodies with an inline error banner; every effect
 * owns an AbortController and aborts on unmount, and no state is written after
 * unmount. Only React is imported (the DSH web client module loader maps
 * 'react' and 'react/jsx-runtime').
 */
const React = __importStar(require("react"));
exports.name = 'dsh-codex-security';
exports.inject = ['slots'];
const API_BASE = '/plugins/codex-security';
const STYLE_ATTR = 'data-dsh-codex-security';
const SCAN_LIMIT = 50;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const FINDING_STATUSES = ['open', 'triaged', 'fixed', 'false_positive', 'accepted_risk', 'wont_fix'];
const EXPORT_FORMATS = [
    { format: 'sarif', label: 'SARIF' }, { format: 'json', label: 'JSON' }, { format: 'csv', label: 'CSV' }, { format: 'markdown', label: 'Markdown' },
];
const SEVERITY_TONE = { critical: 'critical', high: 'error', medium: 'warn', low: 'info', informational: 'muted' };
const SEVERITY_SHORT = { critical: 'crit', high: 'high', medium: 'med', low: 'low', informational: 'info' };
const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
const STATUS_TONE = { completed: 'success', running: 'info', starting: 'info', failed: 'error', canceled: 'warn' };
const MODE_TONE = { deep: 'info', 'prompt-only': 'warn' };
const DISPOSITION_TONE = { reported: 'info', no_issue_found: 'success', needs_follow_up: 'warn', rejected: 'muted', not_applicable: 'muted' };
const CONFIDENCE_TONE = { high: 'success', medium: 'info', low: 'warn' };
function toneOf(map, value) { return (value !== undefined && map[value]) || 'muted'; }
/* ---------------------------------------------------------------- HTTP */
function clip(text, limit) {
    const value = text.replace(/\s+/g, ' ').trim();
    return value.length <= limit ? value : value.slice(0, limit - 1) + '…';
}
function errorMessageOf(value) {
    if (!value || typeof value !== 'object')
        return undefined;
    const record = value;
    const error = record.error;
    if (typeof error === 'string' && error.trim())
        return error.trim();
    if (error && typeof error === 'object' && typeof error.message === 'string') {
        return error.message.trim() || undefined;
    }
    return typeof record.message === 'string' ? record.message.trim() || undefined : undefined;
}
function describeError(error) {
    if (error instanceof Error && error.message)
        return error.message;
    return typeof error === 'string' && error.trim() ? error : 'Unexpected error while talking to the Codex Security plugin.';
}
async function requestJson(url, init) {
    let response;
    try {
        response = await fetch(url, init);
    }
    catch (error) {
        if (error instanceof Error && error.name === 'AbortError')
            throw error;
        throw new Error('Could not reach the Codex Security plugin. ' + describeError(error));
    }
    const text = await response.text().catch(() => '');
    let parsed;
    let parseFailed = false;
    if (text.length > 0) {
        try {
            parsed = JSON.parse(text);
        }
        catch {
            parseFailed = true;
        }
    }
    if (!response.ok) {
        const detail = parseFailed ? undefined : errorMessageOf(parsed);
        throw new Error('HTTP ' + response.status + ' ' + response.statusText + ' from ' + url + ': ' + (detail ?? clip(text, 200) ?? 'no response body'));
    }
    if (parseFailed) {
        throw new Error('Expected JSON from ' + url + ' but the server returned ' + (response.headers.get('content-type') ?? 'an unknown content type') + '.');
    }
    if (parsed && typeof parsed === 'object' && parsed.ok === false) {
        throw new Error(errorMessageOf(parsed) ?? 'The Codex Security server rejected the request.');
    }
    return parsed;
}
function fetchJson(path, signal) {
    return requestJson(API_BASE + path, { method: 'GET', headers: { accept: 'application/json' }, credentials: 'same-origin', signal });
}
function postJson(path, body) {
    return requestJson(API_BASE + path, {
        method: 'POST', credentials: 'same-origin', body: JSON.stringify(body),
        headers: { accept: 'application/json', 'content-type': 'application/json' },
    });
}
/* ---------------------------------------------------------- formatting */
function relativeTime(value, now) {
    if (!value)
        return '—';
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp))
        return '—';
    const seconds = Math.round(Math.max(0, now - timestamp) / 1000);
    if (seconds < 45)
        return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 60)
        return minutes + 'm ago';
    const hours = Math.round(minutes / 60);
    if (hours < 24)
        return hours + 'h ago';
    const days = Math.round(hours / 24);
    return days < 30 ? days + 'd ago' : new Date(timestamp).toLocaleDateString();
}
function absoluteTime(value) {
    if (!value)
        return undefined;
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString() : value;
}
function shortRevision(value) {
    if (typeof value !== 'string' || !value.trim())
        return '—';
    const trimmed = value.trim();
    return trimmed.length <= 8 ? trimmed : trimmed.slice(0, 8);
}
function formatBytes(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0)
        return '';
    if (value < 1024)
        return value + ' B';
    if (value < 1048576)
        return (value / 1024).toFixed(1) + ' KB';
    return (value / 1048576).toFixed(1) + ' MB';
}
function severityOf(finding) {
    const raw = finding.severity?.level;
    return typeof raw === 'string' && SEVERITIES.includes(raw) ? raw : 'informational';
}
function findingStatusOf(finding) {
    const raw = finding.triage?.status ?? finding.status;
    return typeof raw === 'string' && FINDING_STATUSES.includes(raw) ? raw : 'open';
}
function pathLine(finding) {
    const location = finding.locations?.[0];
    if (!location || typeof location.path !== 'string' || !location.path)
        return '—';
    return location.path + (typeof location.startLine === 'number' ? ':' + location.startLine : '');
}
function taxonomyText(finding) {
    const parts = [];
    if (typeof finding.taxonomy?.category === 'string' && finding.taxonomy.category)
        parts.push(finding.taxonomy.category);
    const cwe = finding.taxonomy?.cwe;
    if (typeof cwe === 'string' && cwe)
        parts.push(cwe);
    if (Array.isArray(cwe))
        parts.push(...cwe.filter((entry) => typeof entry === 'string'));
    return parts.join(' · ');
}
function countSeverities(findings, fallback) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    if (findings.length > 0) {
        for (const finding of findings)
            counts[severityOf(finding)] += 1;
        return counts;
    }
    for (const level of SEVERITIES) {
        const value = fallback?.[level];
        if (typeof value === 'number' && Number.isFinite(value))
            counts[level] = value;
    }
    return counts;
}
function exportUrl(scanId, format) {
    return API_BASE + '/export/' + encodeURIComponent(scanId) + '?format=' + format;
}
/* ------------------------------------------------------- presentation */
function Chip({ tone, children }) {
    return (0, jsx_runtime_1.jsx)("span", { className: "dcs-chip", "data-tone": tone, children: children });
}
function SeverityChips({ counts }) {
    const present = SEVERITIES.filter(level => counts[level] > 0);
    if (present.length === 0)
        return (0, jsx_runtime_1.jsx)("span", { className: "dcs-muted", children: "no findings" });
    return ((0, jsx_runtime_1.jsx)("span", { className: "dcs-chips", children: present.map(level => (0, jsx_runtime_1.jsxs)(Chip, { tone: SEVERITY_TONE[level], children: [SEVERITY_SHORT[level], " ", counts[level]] }, level)) }));
}
function Spinner({ label }) {
    return (0, jsx_runtime_1.jsxs)("div", { className: "dcs-loading", role: "status", "aria-live": "polite", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-spinner", "aria-hidden": "true" }), (0, jsx_runtime_1.jsxs)("span", { children: [label, "\u2026"] })] });
}
function Panel({ title, meta, children }) {
    return ((0, jsx_runtime_1.jsxs)("section", { className: "dcs-panel", "aria-label": title, children: [(0, jsx_runtime_1.jsxs)("div", { className: "dcs-panelHead", children: [(0, jsx_runtime_1.jsx)("h3", { className: "dcs-panelTitle", children: title }), meta ? (0, jsx_runtime_1.jsx)("div", { className: "dcs-panelMeta", children: meta }) : null] }), children] }));
}
/* ----------------------------------------------------------- scan list */
function ScanList(props) {
    const { scans, total, selectedId, loading, now, onSelect } = props;
    const meta = total > scans.length ? 'showing ' + scans.length + ' of ' + total : scans.length + ' total';
    return ((0, jsx_runtime_1.jsx)(Panel, { title: "Scans", meta: meta, children: loading && scans.length === 0 ? (0, jsx_runtime_1.jsx)(Spinner, { label: "Loading scans" }) : scans.length === 0 ? ((0, jsx_runtime_1.jsx)("p", { className: "dcs-empty", children: "No scans recorded yet. Start one with the codex_security_start_standard_scan, codex_security_start_prompt_only_scan, or codex_security_start_deep_scan tool." })) : ((0, jsx_runtime_1.jsx)("div", { className: "dcs-tableWrap", children: (0, jsx_runtime_1.jsxs)("table", { className: "dcs-table", children: [(0, jsx_runtime_1.jsx)("thead", { children: (0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Mode" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Status" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Target" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Revision" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Findings" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Updated" })] }) }), (0, jsx_runtime_1.jsx)("tbody", { children: scans.map(scan => {
                            const selected = scan.scanId === selectedId;
                            const select = () => onSelect(scan.scanId);
                            return ((0, jsx_runtime_1.jsxs)("tr", { className: selected ? 'dcs-row dcs-rowSelected' : 'dcs-row', tabIndex: 0, "aria-selected": selected, onClick: select, onKeyDown: event => { if (event.key === 'Enter' || event.key === ' ') {
                                    event.preventDefault();
                                    select();
                                } }, children: [(0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(MODE_TONE, scan.mode), children: scan.mode ?? 'standard' }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(STATUS_TONE, scan.status), children: scan.status ?? 'unknown' }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsxs)("span", { className: "dcs-targetCell", title: (scan.target?.displayName ?? '') + (scan.target?.rootPath ? '\n' + scan.target.rootPath : ''), children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-targetName", children: scan.target?.displayName ?? 'unknown target' }), (0, jsx_runtime_1.jsx)("span", { className: "dcs-targetKind", children: scan.target?.kind ?? '' })] }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: shortRevision(scan.target?.revision) }) }), (0, jsx_runtime_1.jsxs)("td", { children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-findingCount", children: scan.findingsCount ?? 0 }), (0, jsx_runtime_1.jsx)(SeverityChips, { counts: countSeverities([], scan.severityCounts) })] }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("time", { dateTime: scan.updatedAt, title: absoluteTime(scan.updatedAt), children: relativeTime(scan.updatedAt, now) }) })] }, scan.scanId));
                        }) })] }) })) }));
}
/* -------------------------------------------------------- findings list */
function FindingsTable(props) {
    const { scanId, findings, busyFindingId, onTriage } = props;
    const [expandedId, setExpandedId] = React.useState(null);
    const ordered = React.useMemo(() => findings
        .map((finding, index) => ({ finding, index }))
        .sort((left, right) => SEVERITY_RANK[severityOf(right.finding)] - SEVERITY_RANK[severityOf(left.finding)] || left.index - right.index), [findings]);
    if (ordered.length === 0)
        return (0, jsx_runtime_1.jsx)("p", { className: "dcs-empty", children: "No findings recorded for this scan." });
    return ((0, jsx_runtime_1.jsx)("div", { className: "dcs-tableWrap", children: (0, jsx_runtime_1.jsxs)("table", { className: "dcs-table", children: [(0, jsx_runtime_1.jsx)("thead", { children: (0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Severity" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Finding" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Rule" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Location" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Confidence" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Triage" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: (0, jsx_runtime_1.jsx)("span", { className: "dcs-srOnly", children: "Remediation details" }) })] }) }), (0, jsx_runtime_1.jsx)("tbody", { children: ordered.map(({ finding, index }) => {
                        const findingId = typeof finding.findingId === 'string' && finding.findingId ? finding.findingId : 'finding-' + index;
                        const title = finding.title ?? 'Untitled finding';
                        const expanded = expandedId === findingId;
                        const detailId = 'dcs-finding-detail-' + index;
                        const taxonomy = taxonomyText(finding);
                        return ((0, jsx_runtime_1.jsxs)(React.Fragment, { children: [(0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)(Chip, { tone: SEVERITY_TONE[severityOf(finding)], children: severityOf(finding) }) }), (0, jsx_runtime_1.jsxs)("td", { children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-findingTitle", children: title }), taxonomy ? (0, jsx_runtime_1.jsx)("span", { className: "dcs-findingMeta", children: taxonomy }) : null] }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: finding.ruleId ?? '—' }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("code", { className: "dcs-code dcs-location", title: pathLine(finding), children: pathLine(finding) }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(CONFIDENCE_TONE, finding.confidence?.level), children: finding.confidence?.level ?? 'unknown' }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("select", { className: "dcs-select", value: findingStatusOf(finding), disabled: busyFindingId === findingId || !finding.findingId, "aria-label": 'Triage status for ' + title, onChange: event => { if (finding.findingId)
                                                    onTriage(scanId, finding.findingId, event.target.value); }, children: FINDING_STATUSES.map(option => (0, jsx_runtime_1.jsx)("option", { value: option, children: option.replace(/_/g, ' ') }, option)) }) }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)("button", { type: "button", className: "dcs-button dcs-buttonGhost", "aria-expanded": expanded, "aria-controls": detailId, onClick: () => setExpandedId(expanded ? null : findingId), children: expanded ? 'Hide' : 'Details' }) })] }), expanded ? ((0, jsx_runtime_1.jsx)("tr", { id: detailId, className: "dcs-detailRow", children: (0, jsx_runtime_1.jsxs)("td", { colSpan: 7, children: [finding.summary ? (0, jsx_runtime_1.jsx)("p", { className: "dcs-summary", children: finding.summary }) : null, (0, jsx_runtime_1.jsx)("h4", { className: "dcs-subhead", children: "Remediation" }), (0, jsx_runtime_1.jsx)("p", { className: "dcs-remediation", children: finding.remediation ?? finding.triage?.remediation ?? 'No remediation recorded.' }), (0, jsx_runtime_1.jsxs)("p", { className: "dcs-hint", children: [(0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: findingId }), finding.triage?.note ? ' · triage note: ' + finding.triage.note : ''] })] }) })) : null] }, findingId));
                    }) })] }) }));
}
/* --------------------------------------------------------- scan detail */
function ScanDetailPanel(props) {
    const { detail, selectedId, loading, error, busyFindingId, now, onTriage } = props;
    if (!selectedId)
        return (0, jsx_runtime_1.jsx)(Panel, { title: "Scan detail", children: (0, jsx_runtime_1.jsx)("p", { className: "dcs-empty", children: "Select a scan above to inspect its findings, coverage, and artifacts." }) });
    if (!detail) {
        return (0, jsx_runtime_1.jsx)(Panel, { title: "Scan detail", children: loading ? (0, jsx_runtime_1.jsx)(Spinner, { label: "Loading scan details" }) : (0, jsx_runtime_1.jsxs)("p", { className: "dcs-empty", children: [error ?? 'Scan details are unavailable.', " Use Retry to try again."] }) });
    }
    const scan = detail.scan ?? { scanId: selectedId };
    const findings = Array.isArray(detail.findings) ? detail.findings : [];
    const coverage = detail.coverage ?? null;
    const artifacts = Array.isArray(detail.artifacts) && detail.artifacts.length > 0 ? detail.artifacts : (scan.artifacts ?? []);
    const counts = countSeverities(findings, scan.severityCounts);
    const surfaces = coverage?.surfaces ?? [];
    const exclusions = coverage?.explicitExclusions ?? [];
    const deferred = coverage?.deferred ?? [];
    const warnings = scan.warnings ?? [];
    const target = scan.target;
    const progress = scan.progress;
    const scope = scan.scope;
    const inventory = scan.inventory;
    const revision = target?.revision ?? target?.headRevision;
    const scopeText = scope?.summary ?? ((scope?.includePaths?.length ?? 0) + ' include / ' + (scope?.excludePaths?.length ?? 0) + ' exclude paths');
    const inventoryText = typeof inventory?.totalFiles === 'number'
        ? (inventory.inspectedFiles ?? 0) + ' of ' + inventory.totalFiles + ' files inspected' + (inventory.truncated ? ' · truncated' : '')
        : '—';
    const overview = [
        { term: 'Target', value: (target?.displayName ?? '—') + (target?.kind ? ' · ' + target.kind : '') + (target?.remote ? ' · ' + target.remote : '') },
        { term: 'Revision', value: (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: shortRevision(revision) }) },
        { term: 'Scope', value: scopeText },
        { term: 'Inventory', value: inventoryText },
        { term: 'Severity', value: (0, jsx_runtime_1.jsx)(SeverityChips, { counts: counts }) },
    ];
    if (scan.policy)
        overview.push({ term: 'Policy', value: (scan.policy.threshold ?? '—') + ' · ' + (scan.policy.status ?? 'unknown') + (typeof scan.policy.failing === 'number' ? ' · ' + scan.policy.failing + ' failing' : '') });
    if (scan.notes)
        overview.push({ term: 'Notes', value: scan.notes });
    if (scan.error)
        overview.push({ term: 'Error', value: scan.error });
    return ((0, jsx_runtime_1.jsxs)(jsx_runtime_1.Fragment, { children: [(0, jsx_runtime_1.jsxs)("section", { className: "dcs-panel dcs-detailHead", "aria-label": "Selected scan", children: [(0, jsx_runtime_1.jsxs)("div", { className: "dcs-detailHeading", children: [(0, jsx_runtime_1.jsx)("h3", { className: "dcs-detailTitle", title: target?.rootPath, children: target?.displayName ?? 'Unknown target' }), (0, jsx_runtime_1.jsxs)("span", { className: "dcs-detailMeta", children: [(0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(MODE_TONE, scan.mode), children: scan.mode ?? 'standard' }), (0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(STATUS_TONE, scan.status), children: scan.status ?? 'unknown' }), (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: scan.scanId })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "dcs-detailStatus", children: [(0, jsx_runtime_1.jsxs)("span", { className: "dcs-phase", children: ["phase: ", (0, jsx_runtime_1.jsx)("strong", { children: progress?.phase ?? 'unknown' })] }), typeof progress?.discoveryRuns === 'number' ? (0, jsx_runtime_1.jsxs)("span", { children: ["discovery runs: ", progress.discoveryRuns] }) : null, (0, jsx_runtime_1.jsxs)("time", { dateTime: scan.updatedAt, title: absoluteTime(scan.updatedAt), children: ["updated ", relativeTime(scan.updatedAt, now)] }), loading ? (0, jsx_runtime_1.jsx)("span", { className: "dcs-loadingInline", role: "status", children: "Refreshing\u2026" }) : null] })] }), (0, jsx_runtime_1.jsxs)(Panel, { title: "Overview", children: [(0, jsx_runtime_1.jsx)("dl", { className: "dcs-meta", children: overview.map(entry => (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("dt", { children: entry.term }), (0, jsx_runtime_1.jsx)("dd", { children: entry.value })] }, entry.term)) }), (0, jsx_runtime_1.jsx)("h4", { className: "dcs-subhead", children: "Limitations" }), warnings.length === 0 && exclusions.length === 0 && deferred.length === 0 ? ((0, jsx_runtime_1.jsx)("p", { className: "dcs-muted", children: "No warnings, explicit exclusions, or deferred surfaces recorded." })) : ((0, jsx_runtime_1.jsxs)("ul", { className: "dcs-limits", children: [warnings.map((warning, index) => (0, jsx_runtime_1.jsx)("li", { children: warning }, 'warning-' + index)), exclusions.map((entry, index) => (0, jsx_runtime_1.jsxs)("li", { children: ["Excluded ", (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: entry.pattern ?? 'pattern' }), entry.reason ? ': ' + entry.reason : ''] }, 'exclusion-' + index)), deferred.map((entry, index) => (0, jsx_runtime_1.jsxs)("li", { children: ["Deferred ", (0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: entry.id ?? 'surface' }), entry.reason ? ': ' + entry.reason : ''] }, 'deferred-' + index))] }))] }), (0, jsx_runtime_1.jsx)(Panel, { title: "Findings", meta: (0, jsx_runtime_1.jsx)(SeverityChips, { counts: counts }), children: (0, jsx_runtime_1.jsx)(FindingsTable, { scanId: scan.scanId, findings: findings, busyFindingId: busyFindingId, onTriage: onTriage }) }), (0, jsx_runtime_1.jsxs)(Panel, { title: "Coverage", meta: coverage?.mode ? 'mode: ' + coverage.mode : undefined, children: [surfaces.length === 0 ? ((0, jsx_runtime_1.jsx)("p", { className: "dcs-empty", children: "No coverage surfaces recorded for this scan." })) : ((0, jsx_runtime_1.jsx)("div", { className: "dcs-tableWrap", children: (0, jsx_runtime_1.jsxs)("table", { className: "dcs-table", children: [(0, jsx_runtime_1.jsx)("thead", { children: (0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Surface" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Disposition" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Risk area" }), (0, jsx_runtime_1.jsx)("th", { scope: "col", children: "Notes" })] }) }), (0, jsx_runtime_1.jsx)("tbody", { children: surfaces.map((surface, index) => ((0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsxs)("td", { children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-surfaceLabel", children: surface.label ?? surface.id ?? 'unnamed surface' }), (0, jsx_runtime_1.jsx)("code", { className: "dcs-code dcs-surfaceId", children: surface.id ?? '' })] }), (0, jsx_runtime_1.jsx)("td", { children: (0, jsx_runtime_1.jsx)(Chip, { tone: toneOf(DISPOSITION_TONE, surface.disposition), children: (surface.disposition ?? 'unknown').replace(/_/g, ' ') }) }), (0, jsx_runtime_1.jsx)("td", { children: surface.riskArea ?? '—' }), (0, jsx_runtime_1.jsxs)("td", { children: [surface.notes ?? '—', Array.isArray(surface.receiptRefs) && surface.receiptRefs.length > 0 ? ' · ' + surface.receiptRefs.length + ' receipt(s)' : ''] })] }, surface.id ?? 'surface-' + index))) })] }) })), coverage?.inventoryStrategy ? (0, jsx_runtime_1.jsxs)("p", { className: "dcs-hint", children: ["Inventory strategy: ", coverage.inventoryStrategy] }) : null] }), (0, jsx_runtime_1.jsxs)(Panel, { title: "Artifacts & exports", children: [artifacts.length === 0 ? ((0, jsx_runtime_1.jsx)("p", { className: "dcs-empty", children: "No artifacts saved for this scan." })) : ((0, jsx_runtime_1.jsx)("ul", { className: "dcs-artifacts", children: artifacts.map((artifact, index) => ((0, jsx_runtime_1.jsxs)("li", { children: [(0, jsx_runtime_1.jsx)("code", { className: "dcs-code", children: artifact.path ?? 'artifact-' + index }), (0, jsx_runtime_1.jsx)("span", { className: "dcs-artifactSize", children: formatBytes(artifact.size ?? artifact.bytes) })] }, (artifact.path ?? 'artifact') + '-' + index))) })), (0, jsx_runtime_1.jsxs)("div", { className: "dcs-exportRow", role: "group", "aria-label": "Download scan exports", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-exportLabel", children: "Download:" }), EXPORT_FORMATS.map(entry => ((0, jsx_runtime_1.jsx)("a", { className: "dcs-linkButton", href: exportUrl(scan.scanId, entry.format), download: 'codex-security-' + scan.scanId + '.' + (entry.format === 'markdown' ? 'md' : entry.format), "aria-label": 'Download ' + entry.label + ' export for scan ' + scan.scanId, children: entry.label }, entry.format)))] }), (0, jsx_runtime_1.jsx)("p", { className: "dcs-hint", children: "Exports are generated from the sealed findings document." })] })] }));
}
/* ------------------------------------------------------------ workbench */
function Workbench() {
    const [status, setStatus] = React.useState(null);
    const [openFindings, setOpenFindings] = React.useState(null);
    const [scans, setScans] = React.useState([]);
    const [scansTotal, setScansTotal] = React.useState(0);
    const [selectedId, setSelectedId] = React.useState(null);
    const [detail, setDetail] = React.useState(null);
    const [listLoading, setListLoading] = React.useState(true);
    const [detailLoading, setDetailLoading] = React.useState(false);
    const [loadError, setLoadError] = React.useState(null);
    const [actionError, setActionError] = React.useState(null);
    const [reloadToken, setReloadToken] = React.useState(0);
    const [busyFindingId, setBusyFindingId] = React.useState(null);
    const [now, setNow] = React.useState(() => Date.now());
    const mountedRef = React.useRef(true);
    React.useEffect(() => {
        mountedRef.current = true;
        ensureStyles();
        const timer = window.setInterval(() => setNow(Date.now()), 30000);
        return () => { mountedRef.current = false; window.clearInterval(timer); };
    }, []);
    React.useEffect(() => {
        const controller = new AbortController();
        let active = true;
        fetchJson('/status', controller.signal)
            .then(value => { if (active && mountedRef.current)
            setStatus(value); })
            .catch(() => { });
        fetchJson('/findings?status=open&limit=1', controller.signal)
            .then(value => { if (active && mountedRef.current && typeof value.total === 'number')
            setOpenFindings(value.total); })
            .catch(() => { });
        return () => { active = false; controller.abort(); };
    }, [reloadToken]);
    React.useEffect(() => {
        const controller = new AbortController();
        let active = true;
        setListLoading(true);
        fetchJson('/scans?limit=' + SCAN_LIMIT, controller.signal)
            .then(value => {
            if (!active || !mountedRef.current)
                return;
            const next = Array.isArray(value.scans) ? value.scans.filter(scan => scan && typeof scan.scanId === 'string') : [];
            setScans(next);
            setScansTotal(typeof value.total === 'number' ? value.total : next.length);
            setSelectedId(current => next.some(scan => scan.scanId === current) ? current : (next[0]?.scanId ?? null));
            setLoadError(null);
        })
            .catch((error) => {
            if (!active || !mountedRef.current || (error instanceof Error && error.name === 'AbortError'))
                return;
            setLoadError(describeError(error));
        })
            .finally(() => { if (active && mountedRef.current)
            setListLoading(false); });
        return () => { active = false; controller.abort(); };
    }, [reloadToken]);
    React.useEffect(() => {
        if (!selectedId) {
            setDetail(null);
            return;
        }
        const controller = new AbortController();
        let active = true;
        setDetailLoading(true);
        fetchJson('/scans/' + encodeURIComponent(selectedId), controller.signal)
            .then(value => {
            if (!active || !mountedRef.current)
                return;
            setDetail(value);
            setLoadError(null);
        })
            .catch((error) => {
            if (!active || !mountedRef.current || (error instanceof Error && error.name === 'AbortError'))
                return;
            setDetail(null);
            setLoadError(describeError(error));
        })
            .finally(() => { if (active && mountedRef.current)
            setDetailLoading(false); });
        return () => { active = false; controller.abort(); };
    }, [selectedId, reloadToken]);
    const refresh = React.useCallback(() => { setActionError(null); setReloadToken(token => token + 1); }, []);
    const selectScan = React.useCallback((scanId) => { setDetail(null); setSelectedId(scanId); }, []);
    const handleTriage = React.useCallback((scanId, findingId, nextStatus) => {
        setBusyFindingId(findingId);
        setActionError(null);
        postJson('/scans/' + encodeURIComponent(scanId) + '/triage', { findingId, status: nextStatus })
            .then(() => { if (mountedRef.current)
            setReloadToken(token => token + 1); })
            .catch((error) => { if (mountedRef.current)
            setActionError(describeError(error)); })
            .finally(() => { if (mountedRef.current)
            setBusyFindingId(null); });
    }, []);
    const errorText = actionError ?? loadError;
    const scanCount = typeof status?.scans === 'number' ? status.scans : scansTotal;
    const findingCount = typeof status?.findings === 'number' ? status.findings : null;
    return ((0, jsx_runtime_1.jsxs)("section", { className: "dcs-root", "aria-label": "Codex Security workbench", children: [(0, jsx_runtime_1.jsxs)("header", { className: "dcs-header", children: [(0, jsx_runtime_1.jsxs)("div", { className: "dcs-heading", children: [(0, jsx_runtime_1.jsx)("h2", { className: "dcs-title", children: "Codex Security" }), (0, jsx_runtime_1.jsx)("span", { className: "dcs-subtitle", children: "Sealed security scans, findings, and exports" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "dcs-actions", children: [(0, jsx_runtime_1.jsxs)("div", { className: "dcs-headerMeta", children: [(0, jsx_runtime_1.jsxs)("span", { className: "dcs-stat", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-statValue", children: scanCount }), " scans"] }), (0, jsx_runtime_1.jsxs)("span", { className: "dcs-stat", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-statValue", children: findingCount ?? '—' }), " findings"] }), (0, jsx_runtime_1.jsxs)("span", { className: "dcs-stat", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-statValue", children: openFindings ?? '—' }), " open"] })] }), (0, jsx_runtime_1.jsx)("button", { type: "button", className: "dcs-button", onClick: refresh, "aria-label": "Refresh Codex Security data", children: listLoading ? 'Refreshing…' : 'Refresh' })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "dcs-stateDir", children: ["State dir: ", (0, jsx_runtime_1.jsx)("code", { children: status?.stateDir ?? 'unknown' }), typeof status?.version === 'string' ? (0, jsx_runtime_1.jsxs)("span", { className: "dcs-version", children: [" \u00B7 v", status.version] }) : null] }), errorText ? ((0, jsx_runtime_1.jsxs)("div", { className: "dcs-errorBanner", role: "alert", "aria-live": "assertive", children: [(0, jsx_runtime_1.jsx)("span", { className: "dcs-errorMark", "aria-hidden": "true", children: "!" }), (0, jsx_runtime_1.jsx)("span", { className: "dcs-errorText", children: errorText }), (0, jsx_runtime_1.jsx)("button", { type: "button", className: "dcs-button dcs-buttonSmall", onClick: refresh, "aria-label": "Retry loading Codex Security data", children: "Retry" })] })) : null, (0, jsx_runtime_1.jsx)(ScanList, { scans: scans, total: scansTotal, selectedId: selectedId, loading: listLoading, now: now, onSelect: selectScan }), (0, jsx_runtime_1.jsx)(ScanDetailPanel, { detail: detail, selectedId: selectedId, loading: detailLoading, error: actionError ?? loadError, busyFindingId: busyFindingId, now: now, onTriage: handleTriage })] }));
}
/* ----------------------------------------------------- style injection */
const DEFAULT_STYLE = `
.dcs-root{display:flex;flex-direction:column;gap:14px;width:100%;max-width:1040px;color:var(--dsw-alias-label-primary,#e7e8ea);font-size:13px;line-height:20px}
.dcs-root *,.dcs-root *::before,.dcs-root *::after{box-sizing:border-box}
.dcs-root :focus-visible{outline:2px solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary,#4c8dff));outline-offset:2px}
.dcs-header{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;gap:12px}
.dcs-heading{display:flex;flex-direction:column;gap:2px;min-width:0}
.dcs-title{margin:0;font-size:16px;line-height:24px;font-weight:600}
.dcs-subtitle{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}
.dcs-actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.dcs-headerMeta{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.dcs-stat{display:inline-flex;align-items:baseline;gap:4px;padding:1px 8px;border:0.5px solid var(--dsw-alias-border-l2,rgba(255,255,255,.1));border-radius:999px;color:var(--dsw-alias-label-secondary,#b4b6bd);font-size:11px;line-height:18px;white-space:nowrap}
.dcs-statValue{color:var(--dsw-alias-label-primary,#e7e8ea);font-weight:600;font-variant-numeric:tabular-nums}
.dcs-stateDir{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px;overflow-wrap:anywhere}
.dcs-stateDir code,.dcs-code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;color:var(--dsw-alias-label-secondary,#b4b6bd)}
.dcs-version{color:var(--dsw-alias-label-caption,#6f727b)}
.dcs-button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:28px;padding:3px 12px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-md,8px);background:var(--dsw-alias-bg-layer-1,#1c1d21);color:var(--dsw-alias-label-primary,#e7e8ea);font:inherit;font-size:12px;cursor:pointer}
.dcs-button:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}
.dcs-button:disabled{opacity:.55;cursor:default}
.dcs-buttonGhost{padding:2px 8px;min-height:24px;background:transparent;color:var(--dsw-alias-label-secondary,#b4b6bd)}
.dcs-buttonSmall{min-height:24px;padding:1px 10px}
.dcs-linkButton{display:inline-flex;align-items:center;min-height:24px;padding:1px 10px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-md,8px);color:var(--dsw-alias-link,var(--dsw-alias-state-business-primary,#6b9fff));font-size:12px;text-decoration:none}
.dcs-linkButton:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}
.dcs-errorBanner{display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border:0.5px solid var(--dsw-alias-state-error-primary,#ff6b6b);border-radius:var(--dsw-radius-lg,12px);background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#ff6b6b) 10%,transparent)}
.dcs-errorMark{flex:none;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;margin-top:2px;border-radius:50%;background:var(--dsw-alias-state-error-primary,#ff6b6b);color:var(--dsw-alias-label-on-color,#fff);font-size:11px;font-weight:700}
.dcs-errorText{flex:1 1 auto;min-width:0;overflow-wrap:anywhere;color:var(--dsw-alias-state-error-primary,#ff6b6b)}
.dcs-panel{display:flex;flex-direction:column;gap:10px;min-width:0;padding:12px 14px;border:0.5px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l2,rgba(255,255,255,.1)));border-radius:var(--dsw-radius-lg,12px);background:var(--dsw-alias-settings-card-fill,var(--dsw-alias-bg-layer-1,#1c1d21))}
.dcs-panelHead{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}
.dcs-panelTitle{margin:0;font-size:13px;line-height:20px;font-weight:600}
.dcs-panelMeta{display:flex;flex-wrap:wrap;align-items:center;gap:6px;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-loading{display:flex;align-items:center;gap:8px;padding:6px 0;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}
.dcs-spinner{flex:none;width:12px;height:12px;border-radius:50%;border:2px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-top-color:var(--dsw-alias-state-business-primary,#6b9fff);animation:dcs-spin .8s linear infinite}
@keyframes dcs-spin{to{transform:rotate(360deg)}}
.dcs-loadingInline{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-empty{margin:0;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}
.dcs-muted{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-hint{margin:0;color:var(--dsw-alias-label-caption,#6f727b);font-size:11px}
.dcs-subhead{margin:4px 0 0;font-size:11px;line-height:16px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--dsw-alias-label-tertiary,#8a8d95)}
.dcs-tableWrap{width:100%;overflow-x:auto;border-radius:var(--dsw-radius-sm,6px)}
.dcs-table{width:100%;border-collapse:collapse;font-size:12px;line-height:18px}
.dcs-table th{padding:6px 10px;text-align:left;white-space:nowrap;font-size:11px;font-weight:500;color:var(--dsw-alias-label-tertiary,#8a8d95);border-bottom:0.5px solid var(--dsw-alias-border-l2,rgba(255,255,255,.1))}
.dcs-table td{padding:7px 10px;vertical-align:top;border-bottom:0.5px solid var(--dsw-alias-border-l1,rgba(255,255,255,.06))}
.dcs-table tbody tr:last-child td{border-bottom:0}
.dcs-row{cursor:pointer}
.dcs-row:hover td{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}
.dcs-rowSelected td{background:var(--dsw-alias-interactive-bg-active,rgba(255,255,255,.1))}
.dcs-rowSelected td:first-child{box-shadow:inset 2px 0 0 var(--dsw-alias-state-business-primary,#6b9fff)}
.dcs-targetCell{display:flex;flex-direction:column;min-width:0;max-width:240px}
.dcs-targetName{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.dcs-targetKind{color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}
.dcs-findingCount{margin-right:8px;font-weight:600;font-variant-numeric:tabular-nums}
.dcs-chips{display:inline-flex;flex-wrap:wrap;align-items:center;gap:4px;vertical-align:middle}
.dcs-chip{display:inline-flex;align-items:center;gap:4px;padding:0 7px;border:0.5px solid currentColor;border-radius:999px;font-size:10px;line-height:16px;white-space:nowrap;font-variant-numeric:tabular-nums}
.dcs-chip[data-tone=critical]{color:var(--dsw-alias-state-error-primary,#ff6b6b);background:color-mix(in srgb,currentColor 18%,transparent);font-weight:600}
.dcs-chip[data-tone=error]{color:var(--dsw-alias-state-error-primary,#ff6b6b);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=warn]{color:var(--dsw-alias-state-warn-primary,#f0b429);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=success]{color:var(--dsw-alias-state-success-primary,#4ec97a);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=info]{color:var(--dsw-alias-state-business-primary,#6b9fff);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=muted]{color:var(--dsw-alias-label-tertiary,#8a8d95)}
.dcs-select{max-width:130px;padding:2px 6px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-sm,6px);background:var(--dsw-alias-bg-layer-2,#232429);color:var(--dsw-alias-label-primary,#e7e8ea);font:inherit;font-size:11px}
.dcs-select:disabled{opacity:.55}
.dcs-findingTitle{display:block;font-weight:500}
.dcs-findingMeta{display:block;color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}
.dcs-location{display:inline-block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.dcs-detailRow td{background:var(--dsw-alias-bg-layer-2,#232429)}
.dcs-summary{margin:0 0 8px;color:var(--dsw-alias-label-secondary,#b4b6bd)}
.dcs-remediation{margin:0 0 8px;white-space:pre-wrap;overflow-wrap:anywhere}
.dcs-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 18px;margin:0}
.dcs-meta>div{display:flex;flex-direction:column;gap:1px;min-width:0}
.dcs-meta dt{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:10px;text-transform:uppercase;letter-spacing:.04em}
.dcs-meta dd{margin:0;overflow-wrap:anywhere}
.dcs-limits{margin:0;padding-left:18px;color:var(--dsw-alias-label-secondary,#b4b6bd);font-size:12px}
.dcs-limits li{margin:2px 0;overflow-wrap:anywhere}
.dcs-detailHead{gap:6px}
.dcs-detailHeading{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}
.dcs-detailTitle{margin:0;font-size:14px;line-height:22px;font-weight:600;overflow-wrap:anywhere}
.dcs-detailMeta{display:inline-flex;flex-wrap:wrap;align-items:center;gap:6px}
.dcs-detailStatus{display:flex;flex-wrap:wrap;align-items:center;gap:12px;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-phase strong{color:var(--dsw-alias-label-primary,#e7e8ea);font-weight:600}
.dcs-surfaceLabel{display:block}
.dcs-surfaceId{display:block;color:var(--dsw-alias-label-caption,#6f727b)}
.dcs-artifacts{display:flex;flex-direction:column;gap:4px;margin:0;padding:0;list-style:none}
.dcs-artifacts li{display:flex;align-items:baseline;justify-content:space-between;gap:12px}
.dcs-artifactSize{flex:none;color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}
.dcs-exportRow{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.dcs-exportLabel{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-srOnly{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
`;
function ensureStyles() {
    if (typeof document === 'undefined')
        return;
    if (document.querySelector('style[' + STYLE_ATTR + ']'))
        return;
    const element = document.createElement('style');
    element.setAttribute(STYLE_ATTR, '');
    element.textContent = DEFAULT_STYLE;
    document.head.appendChild(element);
}
function apply(ctx) {
    ensureStyles();
    ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'codex-security', order: 41, label: 'Codex Security' }, Workbench));
}

return module.exports;
}});
