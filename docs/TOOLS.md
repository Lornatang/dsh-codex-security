# Tool reference

The plugin registers 27 host tools. Every tool is named with the `codex_security_` prefix
(for example `codex_security_start_standard_scan`), accepts a single JSON object of
arguments and returns one JSON object. The host renders that object as pretty-printed JSON.

```text
codex_security_inspect_setup
codex_security_inspect_target
codex_security_start_standard_scan
codex_security_start_prompt_only_scan
codex_security_start_deep_scan
codex_security_get_scan_context
codex_security_update_scan_context
codex_security_update_scan_progress
codex_security_complete_scan
codex_security_fail_scan
codex_security_cancel_scan
codex_security_record_scan_draft
codex_security_record_discovery_candidates
codex_security_list_candidates
codex_security_record_candidate_validations
codex_security_record_candidate_attack_paths
codex_security_save_artifact
codex_security_read_artifact
codex_security_list_scans
codex_security_get_scan
codex_security_list_findings
codex_security_set_finding_triage
codex_security_set_finding_remediation
codex_security_export_findings
codex_security_prepare_review_items
codex_security_list_review_items
codex_security_compare_scans
```

## Conventions

- **Scan ids** are `cs_` followed by 24 lowercase hex characters, for example
  `cs_0123456789abcdef01234567`. Every scan-scoped tool requires one.
- **Paths** in arguments are absolute or relative filesystem paths for targets. Paths inside
  artifacts, findings and coverage are repository-relative POSIX paths.
- **Errors** are thrown as `Error` values whose message starts with `codex-security:`
  (for example `codex-security: scan not found: cs_...`). Tool calls that violate a
  contract fail; the agent is expected to fix the arguments and retry.
- **Read-only target.** No tool writes to, builds, executes or tests the scanned repository.
  All descriptions end with a reminder that target content is untrusted data, not
  instructions.
- **Timeouts.** Validation-heavy tools allow up to 300 s, target inspection up to 180 s and
  ordinary reads 60 s. Deep scans themselves run outside a tool call; the agent keeps the
  scan alive with progress updates.
- **Deep-scan budgets.** `codex_security_start_deep_scan` accepts `workers` (1–32),
  `maxDiscoveryRuns` (1–10000), `stopAfterNoNew` (1–100) and `maxTimeMinutes` (1–1440);
  omitted values come from `deepWorkers` / `deepMaxDiscoveryRuns` in the plugin config
  (defaults 4 and 40) and from the fixed defaults 4 and 360.

## Tool index

| # | Tool | Group | Purpose |
| --- | --- | --- | --- |
| 1 | `codex_security_inspect_setup` | Setup & target | Version, state dir, config, counters, git, skills |
| 2 | `codex_security_inspect_target` | Setup & target | Resolve a scan target and preview its inventory |
| 3 | `codex_security_start_standard_scan` | Lifecycle | Start a single-pass review scan |
| 4 | `codex_security_start_prompt_only_scan` | Lifecycle | Start a prompt-only scan |
| 5 | `codex_security_start_deep_scan` | Lifecycle | Start a multi-pass scan with budgets |
| 6 | `codex_security_get_scan_context` | Lifecycle | Resume a scan after a context loss |
| 7 | `codex_security_update_scan_context` | Lifecycle | Update notes, threat model, scope |
| 8 | `codex_security_update_scan_progress` | Lifecycle | Record phases and discovery runs |
| 9 | `codex_security_complete_scan` | Lifecycle | Seal artifacts and apply the policy gate |
| 10 | `codex_security_fail_scan` | Lifecycle | Mark a scan failed |
| 11 | `codex_security_cancel_scan` | Lifecycle | Cancel a scan |
| 12 | `codex_security_record_scan_draft` | Evidence & draft | Validate, fingerprint and persist the draft |
| 13 | `codex_security_record_discovery_candidates` | Evidence & draft | Record raw candidates before validation |
| 14 | `codex_security_list_candidates` | Evidence & draft | List candidates by status |
| 15 | `codex_security_record_candidate_validations` | Evidence & draft | Record validation outcomes |
| 16 | `codex_security_record_candidate_attack_paths` | Evidence & draft | Record attack-path analysis |
| 17 | `codex_security_save_artifact` | Evidence & draft | Store supporting evidence under `artifacts/` |
| 18 | `codex_security_read_artifact` | Evidence & draft | Read a saved artifact (bounded) |
| 19 | `codex_security_list_scans` | Findings & review | List scan summaries |
| 20 | `codex_security_get_scan` | Findings & review | Read one scan in full |
| 21 | `codex_security_list_findings` | Findings & review | Query findings across scans |
| 22 | `codex_security_set_finding_triage` | Findings & review | Set triage status and note |
| 23 | `codex_security_set_finding_remediation` | Findings & review | Attach a remediation plan |
| 24 | `codex_security_prepare_review_items` | Findings & review | Create per-file diff review items |
| 25 | `codex_security_list_review_items` | Findings & review | List diff review items |
| 26 | `codex_security_export_findings` | Export & verification | Export SARIF/JSON/CSV/Markdown |
| 27 | `codex_security_compare_scans` | Export & verification | Compare two scans by fingerprint |

---

## Setup & target

### `codex_security_inspect_setup`

Inspect the plugin before the first scan: package version, resolved state directory, effective
configuration, scan counters, git availability and the bundled skill names.

**Arguments:** none.

**Returns**

```json
{
  "ok": true,
  "name": "dsh-codex-security",
  "plugin": "codex-security",
  "version": "0.1.0",
  "stateDir": "/home/user/.dsh/profiles/web/data/codex-security",
  "config": {
    "stateDir": "",
    "maxFiles": 5000,
    "maxFileBytes": 1048576,
    "defaultMode": "standard",
    "failOnSeverity": "high",
    "allowExportOutsideWorkspace": false,
    "maxScanAgeDays": 30,
    "deepWorkers": 4,
    "deepMaxDiscoveryRuns": 40
  },
  "counts": { "scans": 3, "completed": 2, "running": 1, "findings": 7 },
  "git": { "available": true, "version": "git version 2.43.0" },
  "modes": ["standard", "prompt-only", "deep"],
  "skills": ["security-scan", "security-diff-scan", "deep-security-scan", "fix-finding", "verify-fix", "triage-finding", "threat-model", "track-findings", "resolve-dependency-alert", "vulnerability-writeup"],
  "instructions": "Start with codex_security_inspect_target, then start_standard_scan ..."
}
```

**Errors:** none expected beyond plugin initialization failures.

**Example**

```json
{}
```

### `codex_security_inspect_target`

Resolve a target before starting a scan. Detects a git repository or plain directory, resolves
revisions and optional diff facts, inventories reviewable text files, and returns warnings.
This tool performs no writes.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `targetPath` | string | no | Absolute or relative path to the repository or directory. Defaults to the current working directory. |
| `includePaths` | string[] | no | Repository-relative paths to include; defaults to the whole target. |
| `excludePaths` | string[] | no | Repository-relative glob patterns to exclude. |
| `diffTarget` | string | no | Git revision/ref to diff from (for example `origin/main`). Enables diff facts. |
| `workingTree` | boolean | no | Review uncommitted working-tree changes. |

**Returns**

```json
{
  "ok": true,
  "target": {
    "kind": "git_worktree",
    "targetId": "target_0123456789abcdef01234567",
    "displayName": "acme/service",
    "rootPath": "/repos/service",
    "snapshotDigest": "codex-security-snapshot/v1:sha256:...",
    "dirty": false,
    "remote": "https://github.com/acme/service",
    "revision": "3f2a1b0c...",
    "branch": "main"
  },
  "scope": { "includePaths": ["."], "excludePaths": [] },
  "inventory": {
    "totalFiles": 812,
    "inspectedFiles": 640,
    "totalBytes": 5120000,
    "languages": { "ts": 400, "js": 210, "json": 30 },
    "sample": ["src/index.ts", "src/server.ts"],
    "excluded": [".git/**", "node_modules/**"],
    "truncated": false
  },
  "files": ["src/index.ts", "src/server.ts"],
  "fileCount": 640,
  "truncatedFileList": false,
  "warnings": [],
  "nextSteps": ["Call codex_security_start_standard_scan with the same targetPath to bind a scan."]
}
```

For a diff target the response also carries:

```json
{
  "diff": {
    "base": "origin/main",
    "head": "HEAD",
    "workingTree": false,
    "changedFiles": [{ "status": "M", "path": "src/auth.ts" }],
    "changedCount": 1
  }
}
```

**Errors:** path resolution failures and git failures surface as `codex-security:` errors.

**Example**

```json
{ "targetPath": "/repos/service", "diffTarget": "origin/main" }
```

---

## Scan lifecycle

### `codex_security_start_standard_scan`

Bind a target and create a `standard` scan. The response includes the `scanId`, the bound
record and skill instructions for the review workflow. Follow the skill: collect candidates,
record evidence and a draft, then complete the scan.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `targetPath` | string | no | Target repository or directory. Defaults to the current working directory. |
| `includePaths` | string[] | no | Repository-relative paths to include. |
| `excludePaths` | string[] | no | Repository-relative glob patterns to exclude. |
| `notes` | string | no | Review focus or operator context, persisted with the scan. |
| `threatModel` | object | no | Structured threat model persisted on the scan. |
| `previousScanId` | string | no | Earlier scan of the same target when re-reviewing. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_0123456789abcdef01234567",
  "scan": { "scanId": "cs_0123456789abcdef01234567", "mode": "standard", "status": "running" },
  "skill": "security-scan",
  "instructions": "Scan cs_... is bound to acme/service ... Follow the $security-scan skill ... Finish with codex_security_complete_scan."
}
```

**Errors:** invalid target paths; a target with no reviewable text files still creates a scan
but returns a warning in `scan.warnings`.

**Example**

```json
{ "targetPath": "/repos/service", "notes": "Focus on the new upload endpoint." }
```

### `codex_security_start_prompt_only_scan`

Create a `prompt-only` scan. The host agent performs the review from the returned prompt
without deep-scan orchestration. The artifact contract is identical to a standard scan.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `targetPath` | string | no | Target repository or directory. |
| `includePaths` | string[] | no | Repository-relative paths to include. |
| `excludePaths` | string[] | no | Repository-relative glob patterns to exclude. |
| `notes` | string | no | Review focus or operator context. |

**Returns** the standard start response plus `"promptOnly": true` and a `prompt` string.

**Example**

```json
{ "targetPath": "/repos/service" }
```

### `codex_security_start_deep_scan`

Create a `deep` scan: parallel discovery workers with an explicit budget and stop conditions,
followed by validation and attack-path analysis. Best for high-assurance review of a whole
repository.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `targetPath` | string | no | Target repository or directory. |
| `includePaths` | string[] | no | Repository-relative paths to include. |
| `excludePaths` | string[] | no | Repository-relative glob patterns to exclude. |
| `notes` | string | no | Review focus or operator context. |
| `workers` | integer | no | Parallel discovery workers, 1–32. Defaults to `deepWorkers`. |
| `maxDiscoveryRuns` | integer | no | Maximum discovery runs, 1–10000. Defaults to `deepMaxDiscoveryRuns`. |
| `stopAfterNoNew` | integer | no | Consecutive runs without new candidates before stopping, 1–100. Default 4. |
| `maxTimeMinutes` | integer | no | Wall-clock budget in minutes, 1–1440. Default 360. |

**Returns** the standard start response with mode `deep`, plus a `budget` object on the scan
record (`workers`, `maxDiscoveryRuns`, `stopAfterNoNew`, `maxTimeMinutes`, `startedAt`).

**Example**

```json
{ "targetPath": "/repos/service", "workers": 6, "maxDiscoveryRuns": 60 }
```

### `codex_security_get_scan_context`

Read everything needed to resume a scan after a context loss: the record, progress, draft
presence, candidate/validation/attack-path counts, review items, saved artifacts and the
workflow instructions.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id, `cs_<24 hex>`. |

**Returns**

```json
{
  "ok": true,
  "scan": { "scanId": "cs_...", "status": "running", "mode": "deep" },
  "progress": { "phase": "discovering", "notes": ["..."], "discoveryRuns": 7 },
  "draft": { "present": true, "recordedAt": "...", "complete": false, "findingsCount": 3, "surfaces": 4 },
  "candidates": { "total": 12, "byStatus": { "validated": 4, "rejected": 3 }, "validated": 4, "rejected": 3, "validations": 7, "attackPaths": 2 },
  "reviewItems": { "total": 0, "byStatus": {} },
  "artifacts": [{ "path": "artifacts/findings/xss-login/xss-login.md", "bytes": 2048 }],
  "instructions": "Resume with codex_security_record_discovery_candidates ..."
}
```

`draft` is `{ "present": false }` when no draft has been recorded.

**Errors:** `codex-security: scan not found: <scanId>`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567" }
```

### `codex_security_update_scan_context`

Append notes, store a threat model, or adjust the include/exclude scope of a running scan.
Scope changes after target binding are recorded as warnings.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `notes` | string | no | Note appended to the scan record. |
| `threatModel` | object | no | Structured threat model; replaces the stored one. |
| `includePaths` | string[] | no | New include paths; replaces the current list. |
| `excludePaths` | string[] | no | New exclude paths; replaces the current list. |

**Returns** `{ "ok": true, "scan": { ... } }` with the updated record.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "notes": "Threat model refined after reading the API docs." }
```

### `codex_security_update_scan_progress`

Record a progress heartbeat for a long scan: current phase, a short note and optionally one
discovery run. Keeps the workbench state accurate while the review is in progress.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `phase` | string | no | Current phase label, for example `discovering` or `validating`. |
| `note` | string | no | Short progress note; the last 50 notes are kept. |
| `discoveryRun` | boolean | no | Count one discovery run when true. |

**Returns** `{ "ok": true, "scanId": "...", "progress": { "phase": "...", "notes": [...], "discoveryRuns": 8 } }`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "phase": "validating", "discoveryRun": true }
```

### `codex_security_complete_scan`

Seal a scan. Requires a recorded draft. Writes and hashes `findings.json`,
`coverage.json`, `sarif.json` and `report.md` (plus `threat-model.md` when a threat model is
present), adds saved artifacts to the manifest, applies the severity policy gate and marks the
scan `completed`. Only call this when the review and coverage are accounted for.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `threshold` | string | no | Policy threshold override: `informational`, `low`, `medium`, `high`, `critical` or `off`. Defaults to the plugin's `failOnSeverity`. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_0123456789abcdef01234567",
  "status": "completed",
  "sealedAt": "2026-01-01T12:00:00.000Z",
  "findingsCount": 3,
  "severityCounts": { "critical": 0, "high": 1, "medium": 2, "low": 0, "informational": 0 },
  "policy": { "threshold": "high", "status": "fail", "failing": 1 },
  "artifacts": ["coverage.json", "findings.json", "report.md", "sarif.json"],
  "reportPath": "/home/user/.dsh/.../report.md",
  "findingsPath": "/home/user/.dsh/.../findings.json",
  "coveragePath": "/home/user/.dsh/.../coverage.json",
  "manifestPath": "/home/user/.dsh/.../scan-manifest.json",
  "sarifPath": "/home/user/.dsh/.../sarif.json",
  "relative": { "report": "report.md", "findings": "findings.json", "coverage": "coverage.json", "manifest": "scan-manifest.json", "sarif": "sarif.json" },
  "scan": { "scanId": "cs_...", "status": "completed" },
  "nextSteps": ["Export with codex_security_export_findings ..."]
}
```

**Errors**

- `codex-security: scan not found: <scanId>`
- `codex-security: scan already completed: <scanId>`
- `codex-security: scan is <status> and cannot be completed: <scanId>`
- `codex-security: no draft recorded; call codex_security_record_scan_draft before completing the scan`

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "threshold": "medium" }
```

### `codex_security_fail_scan`

Mark a running scan `failed` with a concrete reason. Nothing is sealed; the record and any
collected evidence stay on disk for inspection.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `error` | string | yes | Concrete failure reason. |

**Returns** `{ "ok": true, "scanId": "...", "status": "failed", "error": "..." }`.

**Errors:** a completed scan cannot be failed.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "error": "target repository became unavailable" }
```

### `codex_security_cancel_scan`

Cancel a running scan with an optional reason. Nothing is sealed.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `reason` | string | no | Why the scan was canceled. |

**Returns** `{ "ok": true, "scanId": "...", "status": "canceled", "reason": "..." }`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "reason": "superseded by a scoped re-scan" }
```

---

## Evidence & draft

### `codex_security_record_scan_draft`

Submit the semantic draft: findings and `reviewState.surfaces` covering every reviewed
surface. Findings are validated, normalized, fingerprinted and persisted as
`checkpoints/scan-draft.json`; ids are stable across scans. Call it again to replace the
draft, and always before completing the scan.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `findings` | object[] | yes | Draft findings: `ruleId`, `title`, `summary`, `severity`, `confidence`, `taxonomy`, `locations`, `remediation`, `provenance`, optional `rootCause`, `codeEvidence`, `validation`, `attackPath`, `writeup`. |
| `reviewState` | object | yes | `surfaces` (required), `explicitExclusions`, `deferred`, optional `resolvedDeferred`, `openQuestions`. |
| `scope` | object | no | Scope summary persisted with the draft. |
| `threatModel` | object | no | Structured threat model persisted with the scan. |
| `complete` | boolean | no | Mark the draft complete when discovery and validation are finished. |

Draft findings must not include `findingId`, `occurrenceId` or `fingerprints`; the plugin
assigns them. Full rules are in [ARTIFACTS.md](ARTIFACTS.md).

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_0123456789abcdef01234567",
  "recordedAt": "2026-01-01T11:30:00.000Z",
  "complete": true,
  "findingsCount": 3,
  "severityCounts": { "critical": 0, "high": 1, "medium": 2, "low": 0, "informational": 0 },
  "findings": [{ "findingId": "csf_...", "occurrenceId": "occ_...", "ruleId": "authz.missing-owner-check", "title": "...", "severity": "high", "path": "src/auth.ts", "startLine": 42, "anchor": "...", "fingerprint": "codex-security/v1:sha256:..." }],
  "surfaces": 4,
  "scan": { "scanId": "cs_...", "status": "running" },
  "nextStep": "Call codex_security_complete_scan to seal the scan."
}
```

**Errors:** validation errors such as missing locations, unknown severity levels or malformed
surfaces.

**Example**

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "complete": true,
  "findings": [{
    "ruleId": "authz.missing-owner-check",
    "title": "Project deletion misses an ownership check",
    "summary": "Any authenticated user can delete another user's project by id.",
    "severity": { "level": "high", "score": 8.0 },
    "confidence": { "level": "high", "rationale": "The handler reads the project id from the path and deletes it without comparing the owner." },
    "taxonomy": { "category": "authorization", "cwe": ["CWE-285"] },
    "locations": [{ "path": "src/projects.ts", "startLine": 88, "role": "sink" }],
    "remediation": "Load the project and require project.ownerId === principal.userId before deleting.",
    "provenance": { "source": "agent-review" }
  }],
  "reviewState": {
    "surfaces": [{ "label": "HTTP project routes", "disposition": "reported", "receiptRefs": [] }],
    "explicitExclusions": [],
    "deferred": []
  }
}
```

### `codex_security_record_discovery_candidates`

Record candidate vulnerabilities discovered during review, before validation. Candidates are
deduplicated by rule/anchor/instance and receive stable `cand_` ids; later validation and
attack-path tools reference them.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `candidates` | object[] | yes | `ruleId`, `title`, `severity`, `path`, optional `startLine`, `anchor`, `instance`, `summary`. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_...",
  "added": 8,
  "duplicates": 2,
  "total": 10,
  "candidates": [{ "candidateId": "cand_0123456789abcdef", "ruleId": "...", "title": "...", "severity": "medium", "path": "src/a.ts", "status": "discovered" }]
}
```

**Example**

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "candidates": [{ "ruleId": "ssrf.url-from-request", "title": "Server-side request forgery via user-controlled URL", "severity": "high", "path": "src/fetch.ts", "startLine": 21 }]
}
```

### `codex_security_list_candidates`

List recorded discovery candidates for a scan, optionally filtered by status: `discovered`,
`validating`, `validated`, `rejected` or `reported`.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `status` | string | no | Candidate status filter. |

**Returns** `{ "ok": true, "scanId": "...", "total": 10, "candidates": [ ... ] }`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "status": "discovered" }
```

### `codex_security_record_candidate_validations`

Record validation outcomes: `status` (for example `validated`, `rejected`, `inconclusive`,
`needs_follow_up`), summary, method, evidence and limitations. The candidate status is updated
accordingly. Only validated candidates should become findings.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `validations` | object[] | yes | `candidateId`, `status`, `summary`, optional `method`, `evidence`, `limitations`. |

**Returns** `{ "ok": true, "scanId": "...", "recorded": 3, "validations": [...], "candidates": [...] }`.

**Errors:** `codex-security: unknown candidateId: <id>`.

**Example**

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "validations": [{ "candidateId": "cand_0123456789abcdef", "status": "validated", "summary": "The request URL is passed to fetch without an allow-list.", "method": "static-source-review" }]
}
```

### `codex_security_record_candidate_attack_paths`

Record attack-path analysis for validated candidates: summary, steps, impact, likelihood,
preconditions and controls. Required for high/critical findings in a deep review.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `attackPaths` | object[] | yes | `candidateId`, `summary`, optional `steps`, `impact`, `likelihood`, `preconditions`, `controls`. |

**Returns** `{ "ok": true, "scanId": "...", "recorded": 2, "attackPaths": [ ... ] }`.

**Errors:** `codex-security: unknown candidateId: <id>`.

**Example**

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "attackPaths": [{ "candidateId": "cand_0123456789abcdef", "summary": "An authenticated user supplies an internal metadata URL that the worker fetches.", "steps": ["Open the import dialog", "Paste the metadata URL", "Read the fetched response in the import preview"], "impact": "Cloud credentials disclosure", "likelihood": "medium" }]
}
```

### `codex_security_save_artifact`

Save supporting evidence for a scan: a detailed writeup, proof of concept, threat-model
fragment or review notes. Content is stored under `<scan>/artifacts/<path>` and can be
referenced from coverage `receiptRefs` as `artifacts/<path>`.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `path` | string | yes | Relative path under the scan artifact directory, for example `findings/xss-login/xss-login.md`. |
| `content` | string | yes | UTF-8 text content. |
| `mediaType` | string | no | MIME type; defaults to `text/markdown`. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_...",
  "artifact": { "path": "artifacts/findings/xss-login/xss-login.md", "bytes": 2048, "sha256": "...", "mediaType": "text/markdown", "contentBytes": 2048 }
}
```

**Errors:** paths escaping the artifact directory are rejected.

**Example**

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "path": "findings/xss-login/xss-login.md",
  "content": "# Reflected XSS in the login error page\n\n..."
}
```

### `codex_security_read_artifact`

Read a previously saved scan artifact, bounded to protect the context window. Use it to resume
evidence-based review without re-reading the target.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `path` | string | yes | Artifact path; a leading `artifacts/` is accepted. |
| `limit` | integer | no | Maximum bytes to return, 1024–1048576. Default 262144. |

**Returns** `{ "ok": true, "scanId": "...", "path": "...", "content": "...", "bytes": 2048, "truncated": false }`.

**Errors:** `codex-security: artifact not found: <path>`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "path": "findings/xss-login/xss-login.md" }
```

---

## Findings & review

### `codex_security_list_scans`

List saved scans with status, mode, target, finding counts and severity counts. Filter by
status, mode or target substring. Use it to find previous scans for comparison or triage.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `limit` | integer | no | Page size, 1–200. Default 50. |
| `offset` | integer | no | Page offset. Default 0. |
| `status` | string | no | `starting`, `running`, `completed`, `failed` or `canceled`. |
| `mode` | string | no | `standard`, `prompt-only` or `deep`. |
| `target` | string | no | Case-insensitive display-name substring filter. |

**Returns**

```json
{
  "ok": true,
  "total": 3,
  "limit": 50,
  "offset": 0,
  "scans": [{
    "scanId": "cs_0123456789abcdef01234567",
    "mode": "standard",
    "status": "completed",
    "target": { "displayName": "acme/service", "kind": "git_worktree", "revision": "3f2a1b0c" },
    "createdAt": "2026-01-01T10:00:00.000Z",
    "updatedAt": "2026-01-01T10:20:00.000Z",
    "findingsCount": 5,
    "severityCounts": { "critical": 0, "high": 1, "medium": 3, "low": 1, "informational": 0 },
    "progress": { "phase": "completed" }
  }]
}
```

**Example**

```json
{ "status": "completed", "mode": "standard", "limit": 20 }
```

### `codex_security_get_scan`

Read one scan in full: the record, findings with triage status, the coverage document, a sealed
manifest summary, saved artifacts and review items.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |

**Returns** `{ "ok": true, "scan": {...}, "findings": [...], "coverage": {...} | null, "manifest": { "sealedAt": "...", "artifactCount": 6, "status": "completed" } | null, "artifacts": [...], "triage": {...}, "reviewItems": { "total": 0, "byStatus": {} } }`.

**Errors:** `codex-security: scan not found: <scanId>`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567" }
```

### `codex_security_list_findings`

List findings across completed scans, or for one scan, filtered by severity and triage status.
Each item carries the finding id, fingerprint, locations, remediation and effective triage
status.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | no | Restrict to one scan. Without it, completed scans are queried. |
| `severity` | string | no | `critical`, `high`, `medium`, `low` or `informational`. |
| `status` | string | no | `open`, `triaged`, `fixed`, `false_positive`, `accepted_risk` or `wont_fix`. |
| `limit` | integer | no | 1–500. Default 100. |
| `offset` | integer | no | Page offset. Default 0. |

**Returns** `{ "ok": true, "total": 5, "limit": 100, "offset": 0, "findings": [{ "findingId": "csf_...", "scanId": "cs_...", "severity": "high", "status": "open", ... }] }`.

**Example**

```json
{ "severity": "high", "status": "open" }
```

### `codex_security_set_finding_triage`

Set the triage status of a finding: `open`, `triaged`, `fixed`, `false_positive`,
`accepted_risk` or `wont_fix`, with an optional note. Use `false_positive` only with
evidence.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `findingId` | string | yes | Finding id, `csf_<24 hex>`. |
| `status` | string | yes | New triage status. |
| `note` | string | no | Triage note kept with the finding. |

**Returns** `{ "ok": true, "scanId": "...", "triage": { "csf_...": { "status": "triaged", "note": "..." } } }`.

**Errors:** unknown finding id; invalid status.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "findingId": "csf_0123456789abcdef01234567", "status": "triaged", "note": "Accepted for the next release." }
```

### `codex_security_set_finding_remediation`

Attach a remediation plan to a finding and optionally advance its triage status (default
`triaged`). Use it when writing fixes for review, before verifying them.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `findingId` | string | yes | Finding id. |
| `remediation` | string | yes | Concrete remediation: code change, configuration and verification steps. |
| `status` | string | no | New triage status; defaults to `triaged`. |

**Returns** the same triage shape as `codex_security_set_finding_triage`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "findingId": "csf_0123456789abcdef01234567", "remediation": "Compare project.ownerId with the authenticated user before deleting." }
```

### `codex_security_prepare_review_items`

Prepare per-file review items for a diff scan: lists every changed file (added, modified,
deleted, renamed) so each one is accounted for. Previously recorded item statuses are
preserved. Requires a diff scan (started with `diffTarget` or `workingTree`).

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `files` | string[] | no | Explicit file list instead of the computed diff. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_...",
  "total": 2,
  "byChangeType": { "modified": 1, "added": 1 },
  "byStatus": { "pending": 2 },
  "items": [{ "reviewId": "rev_0123456789abcdef", "path": "src/auth.ts", "changeType": "modified", "status": "pending" }]
}
```

**Errors:** `codex-security: review items require a diff scan (start with diffTarget or workingTree)`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567" }
```

### `codex_security_list_review_items`

List diff-scan review items and their statuses. Every changed file should end `reviewed`,
`no_issue_found`, `rejected`, `not_applicable` or `needs_follow_up`.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `status` | string | no | Status filter. |

**Returns** `{ "ok": true, "scanId": "...", "preparedAt": "...", "total": 2, "byStatus": {...}, "items": [...] }`.

**Errors:** `codex-security: review items have not been prepared for this scan`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "status": "pending" }
```

---

## Export & verification

### `codex_security_export_findings`

Export sealed findings for a scan as `sarif`, `json`, `csv` or `markdown`. Writes to
`<stateDir>/exports/` by default, or to an in-workspace `outputPath`, and returns the absolute
path, byte count and policy gate. Exporting does not re-seal the scan.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `scanId` | string | yes | Scan id. |
| `format` | string | yes | `sarif`, `json`, `csv` or `markdown`. |
| `outputPath` | string | no | Absolute output file path. Must stay inside the workspace or state directory unless `allowExportOutsideWorkspace` is enabled. |

**Returns**

```json
{
  "ok": true,
  "scanId": "cs_0123456789abcdef01234567",
  "format": "sarif",
  "path": "/home/user/.dsh/profiles/web/data/codex-security/exports/cs_0123456789abcdef01234567.sarif.json",
  "bytes": 8192,
  "findingsCount": 5,
  "policy": { "threshold": "high", "status": "fail", "failing": 1 }
}
```

**Errors:** unknown format; scan not completed; `codex-security: refusing to write outside the workspace/state dir; pass an in-workspace outputPath or enable allowExportOutsideWorkspace`.

**Example**

```json
{ "scanId": "cs_0123456789abcdef01234567", "format": "sarif", "outputPath": "/repos/service/reports/security.sarif.json" }
```

### `codex_security_compare_scans`

Compare two scans by stable fingerprint: `closed` (present only in the base scan, typically
fixed), `new` (present only in the head scan, typically regressions) and `open` (present in
both). Use it to verify a fix or track a target over time.

**Arguments**

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `baseScanId` | string | yes | Older scan id. |
| `headScanId` | string | yes | Newer scan id. |

**Returns**

```json
{
  "ok": true,
  "baseScanId": "cs_...base",
  "headScanId": "cs_...head",
  "counts": { "base": 5, "head": 4, "closed": 3, "new": 2, "open": 2 },
  "closed": [{ "findingId": "csf_...", "title": "...", "severity": "high", "path": "src/auth.ts", "startLine": 88, "fingerprint": "codex-security/v1:sha256:..." }],
  "new": [{ "findingId": "csf_...", "title": "...", "severity": "medium", "path": "src/upload.ts", "startLine": 12, "fingerprint": "codex-security/v1:sha256:..." }],
  "open": [{ "findingId": "csf_...", "title": "...", "severity": "low", "path": "src/xml.ts", "startLine": 5, "fingerprint": "codex-security/v1:sha256:..." }]
}
```

The three lists are capped at 200 entries each.

**Errors:** unknown scan ids; scans without sealed findings cannot be compared.

**Example**

```json
{ "baseScanId": "cs_0123456789abcdef01234567", "headScanId": "cs_89abcdef0123456789abcdef" }
```
