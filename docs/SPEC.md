# Implementation specification

The project provides an independent DSH implementation of a skill-driven static security review workbench. The authoritative tool parameter list is [TOOLS.md](TOOLS.md), and the artifact contracts are [ARTIFACTS.md](ARTIFACTS.md) and the JSON Schemas under `schemas/`.

## Product surface

- Package: `@lornatang/dsh-codex-security`; plugin and patch row: `codex-security`.
- Host: 29 `codex_security_*` tools and ten bundled skills. `tools` and `skills` are required Cordis services.
- Client: one **Codex Security** settings section backed by local HTTP routes.
- Scan modes: `standard`, `prompt-only`, `deep`. `codex_security_start_scan` uses the configured default; named start tools select their mode explicitly.
- Deep-scan budgets are recorded for the agent workflow. The host does not launch or supervise discovery workers.

## Configuration

| Key | Default | Contract |
| --- | --- | --- |
| `stateDir` | `""` | Override storage; empty uses the active profile data directory. |
| `maxFiles` | `5000` | Inventory cap, from 1 to 200000. |
| `maxFileBytes` | `1048576` | Maximum bytes used to derive one evidence line. |
| `defaultMode` | `standard` | Default for the generic start tool. |
| `failOnSeverity` | `high` | Policy threshold or `off`. |
| `allowExportOutsideWorkspace` | `false` | Permit explicitly requested exports outside permitted roots. |
| `maxScanAgeDays` | `30` | Workbench age warning; no automatic deletion. |
| `deepWorkers` | `4` | Default recorded worker budget. |
| `deepMaxDiscoveryRuns` | `40` | Default recorded discovery-run budget. |

## Lifecycle and storage

A running scan is bound to an existing directory, scope, revision or working-tree snapshot and, for diffs, a changed-file list. The scope cannot be changed in place. The target is rechecked before completion.

Completion requires a draft marked complete, at least one coverage surface, candidate dispositions, and dispositions for all bound diff files. Explicitly deferred work remains visible in coverage. The plugin validates generated findings, coverage and manifest against the bundled schemas, writes their hashes, then records completed status. Failed and canceled scans are unsealed. Supporting artifacts are immutable after a scan stops running; triage remains editable in a separate record.

Comparison requires completed scans with matching target root, target kind, scan mode and include/exclude paths. Diff scans must share a base revision. Truncated, deferred, missing or incomplete coverage is not comparable. Fingerprint disappearance alone does not prove remediation.

State is local. Scan changes are serialized within one service instance and individual files are written atomically; cross-process access to one state directory is unsupported. The index can be rebuilt from scan records.

## Workbench and routes

The host registers `/plugins/codex-security` routes for status, configuration, scans, findings, triage, remediation and exports. The client displays scan state, findings, coverage, exports and an age warning based on `maxScanAgeDays`. It uses the DSH `settings.section` slot and does not initiate scans itself.

## Security and scope

The host uses read-only Git queries and does not build or execute the reviewed target. Explicit exports can write outside scan storage according to the configured policy. Skills instruct the agent to treat repository content as untrusted and redact secrets; these are agent-workflow requirements rather than host-enforced guarantees.
