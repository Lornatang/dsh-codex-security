# Artifact contracts

A scan is stored at `<stateDir>/repositories/<repoKey>/scans/<scanId>/`. IDs are `cs_` plus 24 lowercase hex characters. The package ships JSON Schemas for findings, coverage and manifests; the host validates all three before accepting a completed seal.

## Files

| File | Purpose | In manifest |
| --- | --- | --- |
| `scan.json` | Internal state, scope, snapshot, progress and diff file list | No |
| `findings.json` | Normalized findings | Yes |
| `coverage.json` | Reviewed surfaces, exclusions and deferred work | Yes |
| `report.md` | Human-readable static review report | Yes |
| `sarif.json` | SARIF 2.1.0 representation | Yes |
| `threat-model.md` | Optional threat model | When present |
| Agent-saved artifacts | Writeups and other supporting files | Yes |
| `checkpoints/scan-draft.json` | Most recent draft checkpoint | No |
| `candidates.json`, `validations.json`, `attack-paths.json` | Candidate ledger | No |
| `review-items.json` | Bound diff file dispositions | No |
| `triage.json` | Separately editable finding status and remediation | No |
| `scan-manifest.json` | Seal metadata and hashes of the listed files | The manifest does not hash itself |

Agent-saved files are scan-relative. Common paths are `findings/<slug>/<slug>.md`, `artifacts/<path>`, `patches/<slug>.patch`, `tests/<slug>-test.md` and `verify/<slug>-verification.md`. Internal scan files and checkpoints cannot be overwritten with `save_artifact`. Supporting artifacts can be written only while a scan is running. Triage is deliberately separate and remains editable after completion.

## Findings

`findings.json` has `documentType: codex-security.findings`, `schemaVersion: 1.0`, the scan ID and a `findings` array. Each normalized finding has a finding ID, occurrence ID, rule ID, identity, fingerprint, title, summary, severity, confidence, taxonomy, locations, remediation and provenance. `taxonomy.cwe` is always an array; a single supplied CWE is normalized to an array and an unspecified CWE becomes `[]`.

The primary fingerprint is `codex-security/v1:sha256:` followed by the SHA-256 of the normalized rule, repository-relative path, anchor and optional instance. The default anchor uses the rule, a path slug and a hash of the normalized evidence line; an explicit anchor can be supplied. Line numbers are excluded from the primary identity, so moving an unchanged evidence line does not itself change the fingerprint. Editing the evidence line, changing the path or rule, or changing the instance can change the fingerprint. Findings with the same primary fingerprint in one draft are deduplicated.

## Coverage

`coverage.json` records the scan mode, inventory strategy, include/exclude paths, surfaces, explicit exclusions, deferred work and optional resolved deferred items and open questions. Surface dispositions are `reported`, `no_issue_found`, `rejected`, `not_applicable` and `needs_follow_up`. Receipt paths must be under `artifacts/`.

A scan cannot be sealed with an incomplete draft or an empty surface list. Each candidate needs a disposition; a candidate marked deferred must be represented in `reviewState.deferred` by candidate ID or path. Diff scans additionally require a recorded review disposition for every bound changed file. These checks validate the submitted record, not whether an agent actually read the claimed code.

## Manifest and snapshot

`scan-manifest.json` contains producer, status, timestamps, target identity and snapshot digest, scope, findings reference and artifact entries with SHA-256 hashes. The manifest mode uses the coverage mode vocabulary. Optional context is omitted when absent; the host does not claim that inventory counts prove files were reviewed.

The snapshot identifies the bound revision and diff list and, for directory and working-tree reviews, the content of inventoried reviewable files. It is rechecked on completion. Default exclusions, the inventory cap and unreadable-file warnings limit what it covers. A revision-only diff is tied to immutable Git revisions. The snapshot is an identity for the review scope, not a hash of every byte in the repository.

## Drafts, comparison and exports

`record_scan_draft` replaces the previous checkpoint. It validates normalized findings against the bundled schema; final sealing requires `complete: true`. Scope is fixed when the scan starts. Completed scans may be compared only if target, mode and scope are compatible and their coverage is not truncated or deferred. Base-only fingerprints are called `closed`, head-only fingerprints `new`, and shared fingerprints `open`; source review is still required to establish a fix.

Exports are available as SARIF, JSON, CSV and Markdown for completed scans. They default to `<stateDir>/exports/`; an explicitly requested destination is subject to the configured path policy and cannot be inside scan storage. The files in [examples/](../examples) illustrate the format and are not necessarily byte-for-byte output from this version.
