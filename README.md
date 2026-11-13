# dsh-codex-security

Agent-native security review workbench for DeepSeek Harness (DSH), modeled on
[OpenAI codex-security](https://github.com/openai/codex-security): an agent performs a
**static security review** of a repository, records its evidence and coverage as **sealed
scan artifacts**, and produces reviewable findings with stable ids, triage state and
SARIF/JSON/CSV/Markdown export.

Requires **DeepSeek Harness >= 0.2.2-rc.2** and **Node.js >= 22.19**.

Published on npm as [`@lornatang/dsh-codex-security`](https://www.npmjs.com/package/@lornatang/dsh-codex-security).

> This is an independent community project. It is not affiliated with or endorsed by
> OpenAI or DeepSeek. The artifact contracts, skill workflows and scan/report model are
> adapted from OpenAI codex-security under the Apache License 2.0 — see [NOTICE](NOTICE).

## What it is

DSH plugins can expose host tools, skills, HTTP routes and client UI. This plugin uses all
four to turn a security review into a structured, auditable artifact set:

- The agent binds a target (repository, scoped path, worktree or diff), inventories the
  reviewable text files and creates a scan record.
- The bundled skills (`$security-scan`, `$security-diff-scan`, `$deep-security-scan`, ...)
  tell the agent how to review source as untrusted data, validate candidates and write
  coverage surfaces.
- The agent records candidates, validations, attack paths and a draft through host tools.
- Completing the scan **seals** `findings.json`, `coverage.json`, `scan-manifest.json` and
  `report.md` in the profile's state directory, with sha256 hashes in the manifest.
- Findings keep stable fingerprints across scans, so fixes can be verified and regressions
  detected by comparing two scans.

Nothing is uploaded: the plugin works on local files only, and it does not build, execute
or test the repository it reviews.

## Features

- **Sealed scans** — every completed scan produces the findings/coverage/manifest contract
  plus a human report; only `completed` scans are sealed. Failed and canceled scans keep
  their record and do not produce a seal.
- **Three scan modes** — `standard` (single evidence-driven pass), `prompt-only` (intake and
  report skeleton without orchestration semantics) and `deep` (repeated passes with a
  worker/discovery budget recorded on the scan).
- **27 host tools** — `codex_security_*` tools for setup, targets, lifecycle, evidence,
  findings/triage, review items, export and scan comparison.
- **10 skills** — agent workflows registered from `skills/` at plugin load.
- **Deep-scan orchestration** — worker count, discovery-run budget, stop-after-no-new and a
  time limit; candidates, validations and attack paths are persisted between passes.
- **Diff review** — binds a commit range, branch or working tree and records one review item
  per changed file (`prepare_review_items` / `list_review_items`).
- **Fix verification** — `compare_scans` classifies findings as closed, open or new by
  fingerprint between a base and a head scan.
- **Exports** — SARIF 2.1.0, JSON, CSV and Markdown, written under the state directory by
  default; `failOnSeverity` records a policy gate result on completion and export.
- **Web workbench** — a **Codex Security** settings section ("代码安全" in Chinese) lists
  scans, shows findings with severity chips and triage state, coverage surfaces and export
  links.
- **Local-only state** — scans live under the profile's data directory and can be deleted
  like any other profile data.

## Installation

Install the package into the DSH profile you use:

```bash
dsh plugin --profile <profile> add @lornatang/dsh-codex-security
```

Replace `<profile>` with your profile name (for example `desktop` or `web`). Then restart
DSH. If you run the web UI from a terminal, restart it with `dsh web --no-open`.

Once the package is listed in the DSH plugin market ([dshmarket](https://dshmarket.com)),
you can also install it from **Plugins → Plugin Market** in the DSH web UI, without a CLI
command. The CLI command above always works.

Uninstall with:

```bash
dsh plugin --profile <profile> remove @lornatang/dsh-codex-security
```

## Quick start

1. Install the plugin and restart DSH (see above).
2. Open the repository you want reviewed in DSH.
3. Ask the agent:

   ```text
   Run a security scan of this repository.
   ```

   Or invoke the skill directly:

   ```text
   $security-scan
   ```

4. The agent inspects the environment (`codex_security_inspect_setup`), binds the target
   (`codex_security_inspect_target`), starts a scan and reviews source. When it is done it
   records a draft and seals the scan with `codex_security_complete_scan`.
5. Review the result in **Settings → Codex Security**, or ask the agent to list scans,
   findings and coverage. Export with `codex_security_export_findings`.

Common variants:

```text
$security-diff-scan        # review a PR, commit range, branch or working-tree diff
$deep-security-scan        # exhaustive, multi-pass scan with a discovery budget
```

The agent may also propose a review directly, for example *"Review my uncommitted changes
for security regressions"*.

## How it differs from codex-security

| | OpenAI codex-security | dsh-codex-security |
| --- | --- | --- |
| Runs in | Codex app / CLI / MCP | DeepSeek Harness plugin (host tools, skills, HTTP routes, web UI) |
| Agent interface | codex-security commands and skills | 27 `codex_security_*` tools + 10 DSH skills |
| Orchestration | Codex agent workflow | DSH agent workflow; deep-scan workers and discovery budget are recorded on the scan |
| Artifacts | Upstream scan-artifact contract | Same findings/coverage/manifest contracts, adapted ids (`cs_*`, `csf_*`, `occ_*`) and DSH-specific fingerprint rules |
| Cloud service | No cloud required | No cloud service, no telemetry, no uploads |
| Code execution | Static review | Static review only: the target is never built, executed or tested |
| Patching | Agent-assisted fixes | The plugin never applies patches; fix skills guide the agent, and `compare_scans` verifies the result |

## Tools at a glance

All tools return a JSON object rendered as pretty JSON. Full reference:
[docs/TOOLS.md](docs/TOOLS.md).

| Group | Tools | Count |
| --- | --- | --- |
| Setup & target | `inspect_setup`, `inspect_target` | 2 |
| Scan lifecycle | `start_standard_scan`, `start_prompt_only_scan`, `start_deep_scan`, `get_scan_context`, `update_scan_context`, `update_scan_progress`, `complete_scan`, `fail_scan`, `cancel_scan` | 9 |
| Evidence & draft | `record_scan_draft`, `record_discovery_candidates`, `list_candidates`, `record_candidate_validations`, `record_candidate_attack_paths`, `save_artifact`, `read_artifact` | 7 |
| Findings & review | `list_scans`, `get_scan`, `list_findings`, `set_finding_triage`, `set_finding_remediation`, `prepare_review_items`, `list_review_items` | 7 |
| Export & verification | `export_findings`, `compare_scans` | 2 |

All names are prefixed `codex_security_` (for example
`codex_security_start_standard_scan`).

## Skills

| Skill | Purpose |
| --- | --- |
| `security-scan` | Full repository or scoped-path security review, sealed as a scan |
| `security-diff-scan` | Security review of a PR, commit, branch or working-tree diff |
| `deep-security-scan` | Exhaustive multi-pass scan with discovery workers and budgets |
| `fix-finding` | Turn a validated finding into a minimal, validated code change |
| `verify-fix` | Re-scan and compare against the base scan to prove a fix |
| `triage-finding` | Record triage status and notes for a finding |
| `threat-model` | Create or update a repository threat model |
| `track-findings` | Track findings across scans (open/closed/new) |
| `resolve-dependency-alert` | Investigate and remediate a dependency advisory |
| `vulnerability-writeup` | Write a disclosure-quality vulnerability report |

Skills are registered at runtime from `skills/<name>/SKILL.md`.

## Configuration

Configure the plugin in your DSH profile patch
(`$DSH_HOME/profiles/<profile>/cordis.patch.yml`, default home `~/.dsh`) under the
`codex-security` plugin row:

```yaml
- id: codex-security
  name: '@lornatang/dsh-codex-security'
  config:
    defaultMode: standard
    failOnSeverity: high
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stateDir` | string (absolute path) | `""` | Override the scan state directory. Empty means `<profile data>/codex-security`. |
| `maxFiles` | integer, 1–200000 | `5000` | Inventory cap per scan. |
| `maxFileBytes` | integer, 1024–67108864 | `1048576` | Maximum bytes read from a single file. |
| `defaultMode` | `standard` \| `prompt-only` \| `deep` | `standard` | Mode used when a start tool omits `mode`. |
| `failOnSeverity` | `informational` \| `low` \| `medium` \| `high` \| `critical` \| `off` | `high` | Policy gate threshold reported on completion and export. |
| `allowExportOutsideWorkspace` | boolean | `false` | Permit export paths outside the working directory and state directory. |
| `maxScanAgeDays` | integer, 1–3650 | `30` | Retention hint used by the workbench. |
| `deepWorkers` | integer, 1–32 | `4` | Default deep-scan worker count. |
| `deepMaxDiscoveryRuns` | integer, 1–10000 | `40` | Default deep-scan discovery-run budget. |

## What a scan produces

A completed scan stores its artifacts under
`<stateDir>/repositories/<repoKey>/scans/<scanId>/`:

```text
scan.json              # internal record (lifecycle, target, inventory, progress)
findings.json          # sealed findings contract
coverage.json          # sealed coverage contract
scan-manifest.json     # sealed manifest with sha256 hashes of artifacts
report.md              # human-readable report
threat-model.md        # optional
candidates.json        # discovery candidates (deep scans)
validations.json       # candidate validations
attack-paths.json      # candidate attack paths
triage.json            # finding triage/remediation state
review-items.json      # diff review items
checkpoints/scan-draft.json
findings/<slug>/<slug>.md   # agent-saved writeups (scan-relative)
artifacts/                  # agent-saved coverage receipts and evidence
```

The contract — fields, id and fingerprint rules, coverage dispositions, manifest hashes,
report sections and SARIF mapping — is documented in
[docs/ARTIFACTS.md](docs/ARTIFACTS.md). JSON examples live in [examples/](examples).

## Security model

- **Read-only target.** The plugin lists and reads files and runs read-only git commands.
  It never writes to the reviewed repository.
- **Static review only.** It does not build, execute or test the target, and it performs no
  network requests. Findings are source-backed claims, not runtime proof.
- **Prompt injection is expected.** Repository content is untrusted data. Skills instruct
  the agent to treat source, comments, documentation and generated files as data, never as
  instructions, and the sealed report records that no instruction found in the target was
  followed.
- **Secrets are redacted.** Skills require credentials and personal data to be redacted to a
  short prefix and a length (for example `AKIA…[redacted, 40 chars]`) with only path and
  line cited; the plugin never contacts services to validate a discovered credential.
- **Local state.** Scans, findings and exports stay on the local filesystem. Export paths
  outside the working/state directory require `allowExportOutsideWorkspace: true`.
- **Explicit exports only.** Everything the plugin writes is under the configured state
  directory except exports explicitly requested by a tool call.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layout, modules, lifecycle, state.
- [docs/TOOLS.md](docs/TOOLS.md) — all 27 tools with arguments, returns, errors, examples.
- [docs/ARTIFACTS.md](docs/ARTIFACTS.md) — the findings/coverage/manifest/draft contract.
- [docs/VALIDATION.md](docs/VALIDATION.md) — acceptance checks and a plugin security checklist.
- [docs/SPEC.md](docs/SPEC.md) — authoritative implementation specification.
- [skills/](skills) — agent workflows; [references/](references) — upstream reference material.

## Requirements

- DeepSeek Harness >= 0.2.2-rc.2 with plugin support.
- Node.js >= 22.19.
- Git is optional. Git repositories get revision, branch, remote and diff scanning; other
  directories are reviewed as directory snapshots.

## Troubleshooting

- **No scans in the workbench.** Complete at least one scan, then refresh; check
  `codex_security_inspect_setup` for the effective `stateDir`.
- **Diff scan falls back to a directory snapshot.** Diff scans require a git repository and
  a resolvable base revision.
- **Export is rejected.** Choose a path inside the working directory or state directory, or
  enable `allowExportOutsideWorkspace`.
- **Plugin not loading.** Confirm the profile you installed into is the profile you run, and
  restart DSH after installation.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The NOTICE records the adaptation
from OpenAI codex-security (Apache-2.0); the DSH host plugin, tools, storage, routing and
client workbench are an independent re-implementation against those contracts.
