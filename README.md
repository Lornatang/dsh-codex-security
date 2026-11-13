# dsh-codex-security

An agent-native, static security review workbench for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It combines host tools, bundled skills, a local scan store and a web workbench. The scan and artifact model is adapted from [OpenAI codex-security](https://github.com/openai/codex-security); this is an independent community project.

The npm package is [`@lornatang/dsh-codex-security`](https://www.npmjs.com/package/@lornatang/dsh-codex-security). The 0.1.1 source contains fixes that are not present in the published 0.1.0 package. The host integration is tested against DSH 0.2.2-rc.2 and requires Node.js 22.19 or later.

## What it does

- Binds a repository, directory, scoped path or Git diff to a scan and records a content-based snapshot of the reviewable files.
- Exposes 29 `codex_security_*` host tools and 10 bundled skills for discovery, validation, coverage, triage, exports and comparison.
- Records the complete changed-file list for a diff, including untracked files when the working tree is in scope. Each bound file needs a disposition before sealing.
- Requires an explicitly complete draft and nonempty coverage before sealing. It rejects unresolved candidates unless they are explicitly deferred in coverage, and rejects a target that changed after binding.
- Seals findings, coverage, a report, SARIF and a manifest containing SHA-256 hashes. Supporting artifacts cannot be added or changed after completion; triage records remain separately editable.
- Compares completed scans only when their target, mode, scope and coverage are compatible. A disappeared fingerprint is a comparison result, not proof of a fix.
- Presents scans, findings, coverage and downloads in **Settings → Codex Security**.

Deep scans store worker and discovery budgets and provide an agent workflow for using them. The host does not itself launch workers or enforce the time and stopping budgets. Review quality and coverage still depend on the agent and evidence recorded.

## Install

```bash
dsh plugin --profile <profile> add github:Lornatang/dsh-codex-security
```

Use the profile that runs the plugin, then restart DSH. The npm installation command can be used once a release containing these fixes is published. To remove the plugin:

```bash
dsh plugin --profile <profile> remove @lornatang/dsh-codex-security
```

The plugin needs the DSH `tools` and `skills` services. If either is absent, Cordis waits for the service before starting the plugin.

## Quick start

Open the repository in DSH and ask the agent to run a security scan, or invoke `$security-scan`. The agent inspects the target, starts a scan, records its findings and coverage, then completes the scan. Review the result in **Settings → Codex Security** or export it with `codex_security_export_findings`.

Use `$security-diff-scan` for a Git change and `$deep-security-scan` for an agent-driven, multi-pass review. Diff scans accept `diffTarget`, `workingTree`, or both. The working-tree option includes staged, unstaged and untracked changes. A revision-only diff is bound to immutable Git revisions; inspect the bound revision when reading its source.

## Tools and skills

All tools accept a JSON object and return JSON. The complete parameter and error reference is in [docs/TOOLS.md](docs/TOOLS.md).

| Group | Tools | Count |
| --- | --- | ---: |
| Setup and target | `inspect_setup`, `inspect_target` | 2 |
| Scan lifecycle | `start_scan`, `start_standard_scan`, `start_prompt_only_scan`, `start_deep_scan`, `get_scan_context`, `update_scan_context`, `update_scan_progress`, `complete_scan`, `fail_scan`, `cancel_scan` | 10 |
| Evidence and drafts | `record_scan_draft`, `record_discovery_candidates`, `list_candidates`, `record_candidate_validations`, `record_candidate_attack_paths`, `save_artifact`, `read_artifact` | 7 |
| Findings and review | `list_scans`, `get_scan`, `list_findings`, `set_finding_triage`, `set_finding_remediation`, `prepare_review_items`, `list_review_items`, `update_review_item` | 8 |
| Export and comparison | `export_findings`, `compare_scans` | 2 |

Tool names have the `codex_security_` prefix. The generic `start_scan` tool uses `defaultMode` unless a mode is supplied; the three named start tools always use their named mode.

The bundled workflows are `security-scan`, `security-diff-scan`, `deep-security-scan`, `fix-finding`, `verify-fix`, `triage-finding`, `threat-model`, `track-findings`, `resolve-dependency-alert` and `vulnerability-writeup`. See [skills/README.md](skills/README.md) for their intended use.

## Configuration

Configure the `codex-security` row in the DSH profile patch at `$DSH_HOME/profiles/<profile>/cordis.patch.yml` (the default DSH home is `~/.dsh`):

```yaml
- id: codex-security
  name: '@lornatang/dsh-codex-security'
  config:
    defaultMode: standard
    failOnSeverity: high
```

| Key | Default | Purpose |
| --- | --- | --- |
| `stateDir` | `""` | Scan storage override; empty uses the profile data directory. |
| `maxFiles` | `5000` | Maximum reviewable files included in the inventory. |
| `maxFileBytes` | `1048576` | Maximum bytes read for deriving a source evidence line. Snapshot hashes stream file contents. |
| `defaultMode` | `standard` | Default for `codex_security_start_scan`: `standard`, `prompt-only` or `deep`. |
| `failOnSeverity` | `high` | Severity threshold recorded in the policy result; `off` disables it. |
| `allowExportOutsideWorkspace` | `false` | Permit explicit exports outside the workspace and state directory. |
| `maxScanAgeDays` | `30` | Age threshold for the workbench warning; it does not delete scans. |
| `deepWorkers` | `4` | Default worker budget recorded for a deep scan. |
| `deepMaxDiscoveryRuns` | `40` | Default discovery-run budget recorded for a deep scan. |

## Scan artifacts

A scan lives under `<stateDir>/repositories/<repoKey>/scans/<scanId>/`. A completed scan includes `findings.json`, `coverage.json`, `report.md`, `sarif.json` and `scan-manifest.json`. It may also contain a threat model, candidate records, review items, a draft checkpoint and supporting evidence. The manifest hashes the sealed output and supporting artifacts.

The plugin validates findings, coverage and the manifest against the bundled JSON Schemas before sealing. [docs/ARTIFACTS.md](docs/ARTIFACTS.md) describes the fields and [examples/](examples) contains illustrative documents.

## Review boundaries

Target files are treated as untrusted data. The plugin does not build, run or test them, and its skills tell the agent to ignore repository instructions and redact secrets. Those are workflow requirements; the host cannot guarantee that an agent follows them or independently prove an agent's review is exhaustive.

Scan data stays in the configured local state directory. Explicit exports may be written into the workspace or another permitted location; exports into scan storage are rejected. State sharing between multiple DSH processes is unsupported. Snapshot hashing covers inventoried reviewable files and the bound diff list; truncation and unreadable files are reported as limitations.

## Development and documentation

```bash
npm ci
npm run typecheck
npm test
```

- [Architecture](docs/ARCHITECTURE.md) — package layout, lifecycle and storage.
- [Tool reference](docs/TOOLS.md) — all tool parameters and behavior.
- [Artifact contracts](docs/ARTIFACTS.md) — schemas, identities and exports.
- [Validation](docs/VALIDATION.md) — automated and isolated host checks.
- [Specification](docs/SPEC.md) — implementation scope.
- [Skills](skills/README.md), [schemas](schemas) and [references](references).

## Troubleshooting

- **Plugin is not active:** verify that the installed and running profiles match, restart DSH, and check that both `tools` and `skills` services are available.
- **Completion is rejected:** finish the draft, account for coverage and candidates, resolve every diff review item, and start a new scan if the bound target changed.
- **Comparison is rejected:** use completed scans of the same target, mode and scope with comparable, non-deferred coverage.
- **Export is rejected:** choose an allowed path outside scan storage or enable `allowExportOutsideWorkspace` for an explicit external export.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for attribution and adaptation details.
