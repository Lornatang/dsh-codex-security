# Artifact contract

A completed scan is a set of files with a fixed meaning. The **findings** and **coverage**
documents are canonical; `report.md`, `sarif.json` and the CSV export are deterministic
projections derived from them. `scan-manifest.json` is the integrity anchor: it records a
sha256 hash for every sealed file.

Everything lives under the scan directory
`<stateDir>/repositories/<repoKey>/scans/<scanId>/`. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full state layout.

## Artifact set

| File | Written when | Media type | Role |
| --- | --- | --- | --- |
| `findings.json` | `complete_scan` | `application/json` | Canonical findings document |
| `coverage.json` | `complete_scan` | `application/json` | Canonical coverage document |
| `report.md` | `complete_scan` | `text/markdown` | Human-readable projection |
| `sarif.json` | `complete_scan` | `application/sarif+json` | SARIF 2.1.0 projection |
| `scan-manifest.json` | `complete_scan` (last) | `application/json` | Sealed manifest with sha256 hashes |
| `threat-model.md` | `complete_scan`, when a threat model exists | `text/markdown` | Rendered threat model |
| `checkpoints/scan-draft.json` | `record_scan_draft` | `application/json` | Latest recorded draft (not sealed) |
| `candidates.json` | discovery tools | `application/json` | Discovery candidates (not sealed) |
| `validations.json` | `record_candidate_validations` | `application/json` | Validation outcomes (not sealed) |
| `attack-paths.json` | `record_candidate_attack_paths` | `application/json` | Attack-path analysis (not sealed) |
| `triage.json` | triage/remediation tools | `application/json` | Triage state (not sealed) |
| `review-items.json` | `prepare_review_items` | `application/json` | Diff review items (not sealed) |
| Agent-saved paths (for example `findings/<slug>/<slug>.md`, `patches/<slug>.patch`, `tests/<slug>-test.md`, `verify/<slug>-verification.md`, `tracking/summary-<date>.md`, `dependency-alerts/<pkg>-<advisory>.md`, `triage/<slug>.md`, `artifacts/<path>`) | `save_artifact` | caller-supplied, default `text/markdown` | Supporting evidence; every saved file is sealed into the manifest |

Only files listed in the manifest's `scan.artifacts` array are part of the seal. The draft,
candidates, validations, attack paths, triage and review items stay mutable local state after
completion; changing them never changes the sealed documents.

`save_artifact` accepts scan-relative POSIX paths and stores them verbatim under the scan
directory. Seven files are written by the plugin itself and cannot be replaced through
`save_artifact`: `scan.json`, `findings.json`, `coverage.json`, `scan-manifest.json`,
`sarif.json`, `report.md` and `threat-model.md` (all at the scan root). In particular, save a
supplementary copy of the threat model as `artifacts/threat-model.md`; the sealed
`threat-model.md` is rendered by `complete_scan` from the scan's threat model.

## `findings.json`

Root document:

```json
{
  "documentType": "codex-security.findings",
  "schemaVersion": "1.0",
  "scanId": "cs_0123456789abcdef01234567",
  "generatedAt": "2026-01-01T12:00:00.000Z",
  "findings": []
}
```

`documentType` is the constant `codex-security.findings`; `schemaVersion` is `"1.0"`.
Findings are sorted by severity (critical first) and then by title.

### Finding fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `findingId` | string | yes | `csf_` + 24 hex; stable identity across scans. |
| `occurrenceId` | string | yes | `occ_` + 24 hex; identity of one occurrence at one location. |
| `ruleId` | string | yes | Normalized rule slug, for example `authz.missing-owner-check`. |
| `identity.anchor` | string | yes | Stable anchor; see *Identity rules*. |
| `identity.instance` | string | no | Disambiguates repeated instances of the same rule at the same anchor. |
| `fingerprints.algorithm` | string | yes | Constant `codex-security/v1`. |
| `fingerprints.primary` | string | yes | `codex-security/v1:sha256:` + 64 hex. |
| `title` | string | yes | Truncated to 300 characters. |
| `summary` | string | yes | Truncated to 8000 characters. |
| `severity.level` | enum | yes | `critical`, `high`, `medium`, `low`, `informational`. |
| `severity.score` | number | no | 0–10. Defaults from the level: 9.5 / 8.0 / 5.0 / 2.0 / 0.0. |
| `severity.scoringSystem` | string | no | For example `CVSS:3.1`. |
| `severity.rationale` | string | no | Why this level applies. |
| `severity.changeConditions` | string | no | What would lower the severity. |
| `confidence.level` | enum | yes | `high`, `medium`, `low`. |
| `confidence.rationale` | string | yes | Truncated to 4000 characters. |
| `taxonomy.category` | string | yes | One of the fixed categories; unknown values normalize to `other`. |
| `taxonomy.cwe` | string[] | yes in schema | CWE ids such as `["CWE-22"]`; the implementation omits the key when no CWE was supplied. |
| `locations` | array | yes | At least one location; each has `path`, `startLine`, optional `endLine`, `role`. |
| `remediation` | string | yes | Concrete fix guidance; truncated to 8000 characters. |
| `rootCause` | string/object | no | Root-cause analysis. |
| `codeEvidence` | array | no | Snippets with `id`, `label`, `path`, `startLine`, `code`, `explanation`. |
| `validation` | object | no | Validation status, method, summary, evidence, limitations. |
| `attackPath` | object | no | Summary, steps, impact, likelihood, preconditions, controls, reachability. |
| `remediationTests` | string[] | no | Tests that would prove the fix. |
| `preventiveControls` | string[] | no | Controls that prevent recurrence. |
| `writeup.reportPath` | string | no | Must match `findings/<slug>/<slug>.md` and point at a saved artifact. |
| `provenance.source` | string | yes | Defaults to `agent-review`; `local_plugin` when the plugin discovered it. |
| `extensions` | object | no | Optional references such as `candidateId`, `ledgerRowId`, `reportId`. |
| `scanId` | string | yes | Echoes the root scan id. |

The normalized category set is: `injection`, `authentication`, `authorization`,
`cryptography`, `secrets`, `injection-deserialization`, `path-traversal`, `ssrf`,
`memory-safety`, `race-condition`, `dependency`, `configuration`,
`information-disclosure`, `business-logic`, `other`.

### Example finding document

```json
{
  "documentType": "codex-security.findings",
  "schemaVersion": "1.0",
  "scanId": "cs_0123456789abcdef01234567",
  "generatedAt": "2026-01-01T12:00:00.000Z",
  "findings": [
    {
      "findingId": "csf_2f6c1a0e9d4b7a3c5e8f1b02",
      "occurrenceId": "occ_7b1e4c2a9f0d3b6e8a5c1d24",
      "ruleId": "authz.missing-owner-check",
      "identity": { "anchor": "authz.missing-owner-check/projects-ts/8f3a1c9d2b4e" },
      "fingerprints": {
        "algorithm": "codex-security/v1",
        "primary": "codex-security/v1:sha256:3d9a1c0f5b8e2a7d4c6f9e1a0b3d5c7e8f2a4b6c9d1e3f5a7b0c2d4e6f8a1b3c"
      },
      "title": "Project deletion misses an ownership check",
      "summary": "Any authenticated user can delete another user's project by id because the handler does not compare the project owner with the caller.",
      "severity": { "level": "high", "score": 8.0, "rationale": "Authenticated users can destroy other tenants' data.", "changeConditions": "An ownership check in the same handler would remove the finding." },
      "confidence": { "level": "high", "rationale": "The handler reads the project id from the path and deletes it without an ownership comparison." },
      "taxonomy": { "category": "authorization", "cwe": ["CWE-285"] },
      "locations": [{ "path": "src/projects.ts", "startLine": 88, "endLine": 92, "role": "sink" }],
      "remediation": "Load the project and require project.ownerId === principal.userId before deleting.",
      "remediationTests": ["Deleting another user's project returns 403 and leaves the project intact."],
      "provenance": { "source": "agent-review" }
    }
  ]
}
```

## Identity rules

Finding identity is the foundation for triage, fix verification and regression detection. All
ids and fingerprints derive from a small, path-based identity string, never from a line
number alone.

1. **Rule normalization.** `ruleId` is lowercased, characters outside `[a-z0-9._/-]` become
   `-`, leading non-alphanumerics are stripped, trailing slashes are removed and the result
   is capped at 96 characters. An empty result becomes `code-security.finding`.
2. **Anchor.** A caller may supply `identity.anchor`, but it must match
   `^[a-z0-9][a-z0-9._/-]*$`. Otherwise the anchor is derived as
   `<rule>/<path-slug>/<evidence-part>`, truncated to 200 characters:
   - `<rule>`: the normalized rule id with non-`[a-z0-9._-]` characters replaced by `-`.
   - `<path-slug>`: the POSIX-relative path slugified to 40 characters, lowercased.
   - `<evidence-part>`: the first 12 hex characters of the sha256 of the normalized
     evidence line at the first location (whitespace collapsed and trimmed); if no line
     text can be read, the first 12 hex of a supplied `instance`, otherwise `anchor`.
3. **Primary fingerprint.**
   `codex-security/v1:sha256:` + sha256 of the NUL-joined tuple
   `['codex-security/v1', ruleId, path, anchor, instance ?? '']`.
4. **Finding id.** `csf_` + first 24 hex characters of
   `sha256('finding' NUL primary)`.
5. **Occurrence id.** `occ_` + first 24 hex characters of
   `sha256('occ' NUL primary NUL path NUL startLine)`.

Consequences:

- Moving a finding down within the same file keeps the anchor (evidence line) and therefore
  the fingerprint and finding id; the occurrence id changes only when `startLine` changes.
- Renaming the file, changing the rule id or supplying a different `instance` produces a new
  identity.
- Within one draft, findings with the same primary fingerprint are deduplicated.
- `compare_scans` matches on `fingerprints.primary`: base-only = `closed`, head-only =
  `new`, both = `open`.

## `coverage.json`

Coverage records what was reviewed, what was explicitly skipped and what remains deferred.
It makes "no findings" an auditable claim rather than an absence of output.

| Field | Type | Notes |
| --- | --- | --- |
| `documentType` | string | Constant `codex-security.coverage`. |
| `schemaVersion` | string | `"1.0"`. |
| `scanId` | string | Scan id. |
| `mode` | enum | `repository`, `scoped_path`, `diff`, `commit`, `branch_diff`, `working_tree`, `deep_repository`. |
| `inventoryStrategy` | enum | `repository`, `scoped_path`, `diff`, `directory`, `custom`. |
| `includePaths` | string[] | Scope include paths. |
| `excludePaths` | string[] | Scope exclude paths. |
| `surfaces` | array | Reviewed surfaces: `id`, `label`, `disposition`, `receiptRefs`, optional `riskArea`, `notes`. |
| `explicitExclusions` | array | `{ pattern, reason }` for each deliberate exclusion. |
| `deferred` | array | `{ id, reason, paths?, surfaceIds? }` for work deferred to a later scan. |
| `openQuestions` | array | Optional `{ question, followUpPrompt? }`. |

Coverage `mode` is derived from the scan: deep scans become `deep_repository`; a diff scan
is `branch_diff` when a base revision was resolved and `diff` otherwise; a directory
snapshot is `repository` when the include list is `["."]` and `scoped_path` otherwise; a
dirty worktree is `working_tree` and a clean one `repository`.

### Surface dispositions

| Disposition | Meaning |
| --- | --- |
| `reported` | The surface was reviewed and produced at least one reportable finding. |
| `no_issue_found` | The surface was reviewed and yielded no reportable issue. |
| `rejected` | A candidate was considered and rejected with evidence. |
| `not_applicable` | The surface does not apply to this target or scope. |
| `needs_follow_up` | Review is incomplete and requires another scan. |

`receiptRefs` must point under `artifacts/` (for example
`artifacts/evidence/xss-login-request.txt`); this is validated when the draft is recorded.
Finding writeups are referenced through `writeup.reportPath` instead, because they live at
`findings/<slug>/<slug>.md`. If a completed scan recorded no surfaces, the plugin stores
`artifacts/scan-summary.md`, records a default surface (id `surface-1`, label
`repository review`) and adds a warning.

### Example coverage document

```json
{
  "documentType": "codex-security.coverage",
  "schemaVersion": "1.0",
  "scanId": "cs_0123456789abcdef01234567",
  "mode": "repository",
  "inventoryStrategy": "repository",
  "includePaths": ["."],
  "excludePaths": [],
  "surfaces": [
    {
      "id": "surface-1",
      "label": "HTTP project routes",
      "disposition": "reported",
      "receiptRefs": ["artifacts/evidence/project-delete-route.txt"],
      "riskArea": "authorization"
    },
    {
      "id": "surface-2",
      "label": "XML import pipeline",
      "disposition": "no_issue_found",
      "receiptRefs": []
    }
  ],
  "explicitExclusions": [{ "pattern": "vendor/**", "reason": "Third-party code outside the review scope." }],
  "deferred": [{ "id": "deferred-1", "reason": "Deployment manifests are reviewed separately.", "paths": ["deploy/"] }]
}
```

## `scan-manifest.json`

The manifest is written last and lists every sealed file with its sha256 hash. It is the only
document that describes the seal itself.

```json
{
  "documentType": "codex-security.scan-manifest",
  "schemaVersion": "1.0",
  "scan": {
    "id": "cs_0123456789abcdef01234567",
    "producer": { "name": "@lornatang/dsh-codex-security", "version": "0.1.0" },
    "status": "completed",
    "startedAt": "2026-01-01T11:45:00.000Z",
    "completedAt": "2026-01-01T12:00:00.000Z",
    "sealedAt": "2026-01-01T12:00:00.000Z",
    "target": {
      "kind": "git_worktree",
      "targetId": "target_0123456789abcdef01234567",
      "displayName": "acme/service",
      "remote": "https://github.com/acme/service",
      "revision": "3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a",
      "snapshotDigest": "codex-security-snapshot/v1:sha256:ed88f96a4c1a06603a41b3f261f59c3de2555c367ef6ad3bb8b9e483495d34eb"
    },
    "scope": {
      "includePaths": ["."],
      "excludePaths": [],
      "runtimeStatus": "not_executed",
      "validationMode": "static_source_review",
      "limitations": []
    },
    "findingsRef": "findings.json",
    "artifacts": [
      { "path": "coverage.json", "sha256": "…64 hex…", "mediaType": "application/json" },
      { "path": "findings.json", "sha256": "…64 hex…", "mediaType": "application/json" },
      { "path": "report.md", "sha256": "…64 hex…", "mediaType": "text/markdown" },
      { "path": "sarif.json", "sha256": "…64 hex…", "mediaType": "application/sarif+json" },
      { "path": "findings/project-delete/project-delete.md", "sha256": "…64 hex…", "mediaType": "text/markdown" }
    ],
    "mode": "standard",
    "warnings": [],
    "review": { "excludedPaths": [] }
  }
}
```

Notes:

- `status` is `completed` for a sealed scan; the schema also reserves `failed`,
  `canceled` and `interrupted` for other receipt shapes.
- `target.kind` is one of `git_revision`, `git_worktree`, `git_diff`,
  `directory_snapshot`. `git_revision` requires `revision`; the other kinds require
  `snapshotDigest` matching `codex-security-snapshot/v1:sha256:<64 hex>`.
- `artifacts` must contain `findings.json` exactly once. The plugin also seals
  `coverage.json`, `report.md`, `sarif.json`, an optional `threat-model.md`, and every
  file saved through `save_artifact` at its scan-relative path (for example
  `findings/xss-login/xss-login.md` or `artifacts/evidence/request.txt`), sorted by path.
  Saved files keep the media type given to `save_artifact`; unknown types default to
  `text/markdown`.
- `scan.mode` and `scan.review` are present when `coverageRef` is absent; the plugin does
  not emit `coverageRef`.
- `remote` must not embed credentials, query strings or fragments.
- `scope.limitations` carries the scan warnings; `scope.summary` appears when the scan has
  one.

## Draft checkpoint

`record_scan_draft` persists `checkpoints/scan-draft.json`:

```json
{
  "scanId": "cs_0123456789abcdef01234567",
  "recordedAt": "2026-01-01T11:50:00.000Z",
  "complete": true,
  "input": {
    "scanId": "cs_0123456789abcdef01234567",
    "complete": true,
    "scope": { "summary": "Project service review." },
    "findings": [
      {
        "ruleId": "authz.missing-owner-check",
        "title": "Project deletion misses an ownership check",
        "summary": "Any authenticated user can delete another user's project by id.",
        "severity": { "level": "high", "score": 8.0 },
        "confidence": { "level": "high", "rationale": "The handler never compares the project owner." },
        "taxonomy": { "category": "authorization", "cwe": ["CWE-285"] },
        "locations": [{ "path": "src/projects.ts", "startLine": 88 }],
        "remediation": "Require project.ownerId === principal.userId before deleting.",
        "provenance": { "source": "agent-review" },
        "writeup": { "reportPath": "findings/project-delete/project-delete.md" }
      }
    ],
    "reviewState": {
      "surfaces": [{ "label": "HTTP project routes", "disposition": "reported" }],
      "explicitExclusions": [],
      "deferred": [],
      "openQuestions": [{ "question": "Are project ids guessable?" }]
    }
  },
  "findings": [
    {
      "findingId": "csf_2f6c1a0e9d4b7a3c5e8f1b02",
      "occurrenceId": "occ_7b1e4c2a9f0d3b6e8a5c1d24",
      "ruleId": "authz.missing-owner-check",
      "identity": { "anchor": "authz.missing-owner-check/projects-ts/8f3a1c9d2b4e" },
      "fingerprints": { "algorithm": "codex-security/v1", "primary": "codex-security/v1:sha256:…" },
      "title": "Project deletion misses an ownership check",
      "summary": "Any authenticated user can delete another user's project by id.",
      "severity": { "level": "high", "score": 8.0 },
      "confidence": { "level": "high", "rationale": "The handler never compares the project owner." },
      "taxonomy": { "category": "authorization", "cwe": ["CWE-285"] },
      "locations": [{ "path": "src/projects.ts", "startLine": 88 }],
      "remediation": "Require project.ownerId === principal.userId before deleting.",
      "provenance": { "source": "agent-review" },
      "scanId": "cs_0123456789abcdef01234567"
    }
  ]
}
```

Draft rules:

- `findings` and `reviewState.surfaces` are required. Surfaces need a non-empty `label`
  and a valid `disposition`; `receiptRefs` must start with `artifacts/`.
- Draft findings must **not** include `findingId`, `occurrenceId` or `fingerprints`; the
  plugin assigns them and normalizes the rest.
- A finding may set `writeup.reportPath` to a scan-relative `findings/<slug>/<slug>.md`
  path. Save that file with `save_artifact` before completing the scan so it is hashed into
  the manifest and linked from the report.
- `complete: false` marks a checkpoint: discovery is unfinished and provisional candidates
  belong in `reviewState.deferred`. Completing a scan from an incomplete draft is allowed
  but records a warning.
- Re-recording replaces the whole checkpoint; findings with the same primary fingerprint are
  deduplicated.
- The draft is not sealed. It is excluded from `scan.artifacts`.

## `report.md`

The report is a deterministic projection of the sealed documents; editing it does not change
the contract. Sections, in order:

1. `# Security review: <displayName>`
2. Field table: Scan, Mode, Status, Sealed, Target, Revision (optional Base revision /
   Remote), Snapshot, Scope, Excluded, Files reviewed.
3. `## Executive summary` — severity counts with a Total row, then coverage disposition
   counts.
4. `## Findings` — one block per finding:
   `### N. [SEVERITY] Title`, then Finding/Occurrence ids, Rule/Category/CWE, Severity and
   rationale, Confidence, Locations (`path:start-end (role)`), the summary, optional Root
   cause / Validation / Attack path (numbered steps), Remediation, and a Writeup path.
   With no findings the section says static review cannot prove absence of vulnerabilities.
5. `## Coverage` — table of Surface, Disposition, Risk area, Receipts (or a note that no
   surfaces were recorded).
6. `## Explicit exclusions` — only when non-empty.
7. `## Deferred work` — only when non-empty.
8. `## Open questions` — only when non-empty.
9. `## Threat model` — only when a threat model exists: markdown as-is, otherwise pretty
   JSON.
10. `## Limitations` — four fixed statements: static source review, candidate risk vs
    confirmed behavior, bounded depth from coverage/exclusions/deferred items, and the target
    treated as read-only untrusted data.

## SARIF export

`sarif.json` and the SARIF export share one mapping (SARIF 2.1.0):

- `$schema`: `https://json.schemastore.org/sarif-2.1.0.json`, `version`: `2.1.0`.
- One run; `tool.driver` = `{ name: "codex-security", semanticVersion: "0.1.0", informationUri }`.
- One rule per distinct `ruleId`: `id`, `name`, `shortDescription.text` = category,
  `properties` = `{ category, cwe? }`.
- `originalUriBaseIds["%SRCROOT%"]` = `file://<absolute target root>`.
- Results sorted like findings; each has `ruleId`, `ruleIndex`, `level`,
  `message.text` = `"<title>: <summary>"`, one physical location (path relative to
  `%SRCROOT%`, start/end line), `fingerprints` = `{ "codex-security/v1": primary,
  findingId }`, and `properties` = `{ "security-severity": score.toFixed(1),
  confidence, category, cwe? }`.
- Severity mapping: `critical`/`high` → `error`, `medium` → `warning`,
  `low`/`informational` → `note`.

The SARIF projection is intentionally lossy: coverage, lifecycle, validation and attack-path
detail are not represented, and no `toolExecutionNotifications` are emitted. Treat
`findings.json` as the canonical record.

## CSV export

Header and column order:

```text
finding_id,occurrence_id,severity,confidence,rule_id,title,path,start_line,end_line,category,cwe,remediation
```

Fields containing a quote, comma, CR or LF are quoted with doubled quotes; `end_line` is
empty when absent; the file ends with a newline.

## Schema strictness notes

The JSON Schemas under `schemas/` are the shared contract with upstream codex-security and
are slightly stricter than the current plugin output in a few places. These are known
differences, not features:

- `schemas/definitions/artifact-common.schema.json` declares `scanId` as a UUID; the plugin
  uses `cs_<24 hex>` everywhere.
- `schemas/scan-manifest.schema.json` declares `scan.scope.artifactsReviewed` as a string
  list; the plugin writes the inspected-file count (an integer).
- The same schema declares `scan.scope.context` as a string; the plugin writes `null`
  when there are no scan notes.
- `findings.schema.json` requires `taxonomy.cwe` on every finding; the plugin omits the
  key when the agent supplied no CWE.
- A recorded draft may use `reviewState.resolvedDeferred`; it is accepted by the draft
  schema but currently not projected into `coverage.json`.
- Files under `examples/` illustrate the upstream contract and are not byte-identical to
  this plugin's output (for example, the example producer is `codex-security-plugin` and
  example scan ids are not `cs_` ids).
