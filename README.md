---
description: "An artifact-backed security review layer for a dsh profile: 31 host tools, 16 bundled skills, and a Web workbench that seal schema-validated scans, findings, coverage, and exports under the profile data directory."
kind: "package-bundle"
---

# @lornatang/dsh-codex-security

English | [中文](README.zh.md)

## Summary

`dsh-codex-security` adds a reproducible security review workflow to a dsh profile. It registers 31 `codex_security_*` host tools, 16 bundled skills, and a Codex Security section in the Web GUI that lists scans, findings, coverage, and exports. The `add` command inserts one patch row into the profile and `remove` takes it out. The bundle records and validates agent reviews and can coordinate independent Deep workers. It never executes target code, and completed scans seal immutable artifacts under the profile data directory.

## Table of Contents

- [Use this package](#use-this-package)
- [Understand the implementation](#understand-the-implementation)
- [Further Exploration](#further-exploration)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-package"></a>
## Use this package

The layer gives an agent a durable place to record a security review and gives the profile a Web panel to read and export the result: every scan binds its target, revision, and scope, keeps candidates and validations between turns, and seals a schema-checked artifact set on disk.

### Install into a profile

```text
dsh plugin --profile <name> add @lornatang/dsh-codex-security
dsh plugin --profile <name> remove @lornatang/dsh-codex-security
```

For the GitHub 0.1.10 release, use `dsh plugin --profile <name> add https://github.com/Lornatang/dsh-codex-security/releases/download/v0.1.10/lornatang-dsh-codex-security-0.1.10.tgz`. The npm registry version may be older.

The `add` command composes the layer into the profile: the profile's `cordis.patch.yml` gains an insert entry, row id `codex-security`, whose `config` starts from the bundle defaults `maxFiles: 5000`, `maxFileBytes: 1048576`, and `defaultMode: standard`; every other field takes its default from `src/config.ts`. The package manifest points `dsh.bundle.patch` at that document. The `remove` command deletes the row and leaves scans already written under the profile data directory untouched.

Restart DSH after installing or removing, because the row is composed when the profile starts. On start the plugin logs `codex-security: registered 16 skills` and `codex-security: ready (state dir will resolve on first scan)`, and the Web GUI gains a Codex Security entry under Settings; profiles that do not run the Web client still receive the tools and skills.

A new profile starts with no scans. The first request that touches the store — the workbench status request or `codex_security_inspect_setup` — resolves the state directory and creates `<stateDir>/repositories/`; a scan record appears only after one of the start tools runs, and the plugin itself reviews nothing.

Scans live under `<stateDir>/repositories/<repoKey>/scans/<scanId>/`, where `repoKey` is the first 16 hexadecimal characters of the target root's SHA-256 and `scanId` is `cs_` plus 24 hexadecimal characters; `<stateDir>` defaults to `data/codex-security` next to the profile's `cordis.patch.yml` (for the shipped Web profile, `$DSH_HOME/profiles/web/data/codex-security`). `scan.json` holds the bound target, scope, inventory, progress, and diff list; `index.json` is a rebuildable list cache. Completion requires a draft submitted with `complete: true`, at least one coverage surface, a final disposition for every candidate and every bound diff file, and an unchanged snapshot digest; the plugin then validates the findings, coverage, and manifest documents against `schemas/`, records hashes in `scan-manifest.json`, and seals the scan. Sealed artifacts are immutable, triage is stored separately and stays editable, and exports default to `<stateDir>/exports/<scanId>.<format>`.

Repeated default exports receive a numbered suffix; an explicitly supplied output path must not already exist.

### What you get

The package owns three surfaces in the composed profile: 31 host tools, 16 skills, and one workbench section in the Web GUI. [docs/TOOLS.md](docs/TOOLS.md) documents each tool's arguments and return shape; [docs/CODEX-COMPATIBILITY.md](docs/CODEX-COMPATIBILITY.md) compares the implementation with Codex Security.

- **Setup and target inspection:** `codex_security_inspect_setup`, `codex_security_inspect_target`.
- **Scan lifecycle:** `codex_security_start_scan`, `codex_security_start_standard_scan`, `codex_security_start_prompt_only_scan`, `codex_security_start_deep_scan`, `codex_security_resume_deep_scan`, `codex_security_get_deep_scan_status`, `codex_security_get_scan_context`, `codex_security_update_scan_context`, `codex_security_update_scan_progress`.
- **Discovery and candidates:** `codex_security_record_discovery_candidates`, `codex_security_list_candidates`.
- **Validation:** `codex_security_record_candidate_validations`, `codex_security_record_candidate_attack_paths`.
- **Draft and sealing:** `codex_security_record_scan_draft`, `codex_security_complete_scan`, `codex_security_fail_scan`, `codex_security_cancel_scan`.
- **Agent artifacts:** `codex_security_save_artifact`, `codex_security_read_artifact`.
- **Findings and triage:** `codex_security_list_findings`, `codex_security_set_finding_triage`, `codex_security_set_finding_remediation`.
- **Diff review:** `codex_security_prepare_review_items`, `codex_security_list_review_items`, `codex_security_update_review_item`.
- **Review and comparison:** `codex_security_list_scans`, `codex_security_get_scan`, `codex_security_compare_scans`.
- **Export:** `codex_security_export_findings`.

The skill catalog gains 16 entries, each loaded from `skills/<name>/SKILL.md` at startup with `source: bundled` and both model and user invocation: `security-scan`, `security-diff-scan`, `deep-security-scan`, `fix-finding`, `verify-fix`, `triage-finding`, `threat-model`, `track-findings`, `resolve-dependency-alert`, `vulnerability-writeup`, `assess-patch-risk`, `attack-path-analysis`, `define-security-policy`, `finding-discovery`, `propose-security-hardening`, and `validation`; [skills/](skills/) holds the workflow text for each.

The Web GUI gains one `settings.section` row, id `codex-security`, order 41, label Codex Security, registered by this package's client half (`src/client/index.tsx`, shipped as `lib/client.js`) through `@deepseek-ai/dsh-client-ui-slots` and `@deepseek-ai/dsh-client-ui-settings`. The panel shows the version, the resolved state directory, and scan and finding counts; it lists scans with status and age, and opens the selected scan's Overview, Findings, Coverage, and Artifacts & exports panels, including a triage selector and download links for SARIF, JSON, CSV, and Markdown. The panel reads the same service through HTTP routes under `/plugins/codex-security`.

### Configuration

The bundle ships the row below, so a profile only lists what differs from it; the profile's own entry is applied after the layer and wins. The loader validates each field against `src/config.ts` and rejects an invalid value at startup instead of substituting a default.

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: codex-security
  config:
    maxFiles: 5000
    maxFileBytes: 1048576
    defaultMode: standard
    failOnSeverity: high
    allowExportOutsideWorkspace: false
    maxScanAgeDays: 30
    deepWorkers: 4
    deepMaxDiscoveryRuns: 40
    # stateDir: /var/lib/dsh/codex-security
```

| Field | Default | Meaning |
|---|---|---|
| `stateDir` | empty | Directory that holds scans and exports. Empty resolves to `data/codex-security` next to the profile's `cordis.patch.yml`, or to `$DSH_HOME/profiles/web/data/codex-security` when no profile patch path is available. |
| `maxFiles` | `5000` | Files inventoried per target, 1–200000; truncation is recorded as a scan warning. |
| `maxFileBytes` | `1048576` | Per-file size cap for the reviewable inventory, 1024–67108864 bytes. |
| `defaultMode` | `standard` | Mode used by `codex_security_start_scan`: `standard`, `prompt-only`, or `deep`. |
| `failOnSeverity` | `high` | Policy gate threshold: `informational`, `low`, `medium`, `high`, `critical`, or `off`. |
| `allowExportOutsideWorkspace` | `false` | Permits exports outside the state directory, the process working directory, and the target root. |
| `maxScanAgeDays` | `30` | Age at which the workbench marks a scan as older than the policy window, 1–3650 days. |
| `deepWorkers` | `4` | Maximum concurrent Deep workers, 1–32. |
| `deepMaxDiscoveryRuns` | `40` | Maximum Deep discovery attempts, 1–10000. |

### Automatic Deep scans

Call `codex_security_start_deep_scan` to start independent workers; keep the returned `recoveryClaim` private. Check `codex_security_get_deep_scan_status`, and resume with `codex_security_resume_deep_scan` after a process exits. The original session can resume without the claim; another session needs it for resume or cancellation. `workers`, `maxDiscoveryRuns`, `stopAfterNoNew`, and `maxTimeMinutes` bound orchestration. Interrupted attempts consume the run budget. The target directory identity is fixed at start; file contents are bound during the asynchronous initialization phase. The configured DSH model provider receives source text and may use the network.

Automatic mode requires the local DSH `spawn` provider, agent-preset registry, native executor, and matching optional filesystem binary. The standard Web profile supplies the first three; profiles without them fail closed. Automatic Deep accepts repository or directory snapshots, not diffs. Use `manual: true` for the manual workflow. Workers can only read verified, bound source chunks and submit structured output. A zero-finding result requires a complete worker with accepted full-file reads; a receipt proves delivery rather than comprehension.

-----

<a id="understand-the-implementation"></a>
## Understand the implementation

<details>
<summary>Implementation internals — click to expand</summary>

The layer is one patch row: an `insert` of id `codex-security`, package name `@lornatang/dsh-codex-security`, and three config values. Nothing is platform-gated on the host side; the manifest's `dsh.client.platform: web` scopes only the client bundle, while the host plugin registers tools and skills in any profile that injects them.

Cordis must inject `tools` and `skills` before `apply` runs. `apply` builds a `SecurityService` from the resolved config and the profile patch path, then registers the 31 tools, discovers and registers the 16 bundled skills from `skills/*/SKILL.md`, and binds optional HTTP routes, each in a disposal-aware effect. The state directory is not created at startup; `ScanStore.init` creates it on the first store access.

A start tool resolves the target, binds revisions or diff facts, inventories reviewable files within the caps, computes a snapshot digest, and writes `scan.json` under the scan directory. Later tools append the draft, candidates, validations, attack paths, review items, and saved artifacts, with a per-scan queue serializing mutations. Completion re-resolves the target, rejects a changed digest, checks the draft and coverage contract, builds the findings, coverage, SARIF, and Markdown documents, validates the findings, coverage, and manifest documents against the bundled schemas, and writes the manifest that seals the scan.

The workbench reaches the same service through `handleRequest` under `/plugins/codex-security`, registered on `webServer` or `httpServer` when one exists. The client half is compiled separately to CommonJS and wrapped for the DSH module loader; it injects into `settings.section` and fetches those routes. The coordinator uses the configured DSH model provider to dispatch isolated static-review workers; the provider may use the network. Workers cannot execute target code.

SQLite OS locks serialize campaign ownership, scan mutations and index updates across processes. JSON files use same-directory atomic replacement. Shared state requires a trusted local directory on a filesystem with reliable SQLite locking; individual files are atomic but a full seal is not one transaction.

| Source | Contents |
|---|---|
| `cordis.patch.yml` | The layer: one insert entry, row id `codex-security`, three config defaults. |
| `src/index.ts` | Host entry: `apply`, configuration export, bundled-skill discovery and registration. |
| `src/config.ts` | `Config` interface, `DEFAULT_CONFIG`, and the schema ranges enforced at startup. |
| `src/constants.ts` | Package and plugin names, version, route prefix, tool and skill name inventories. |
| `src/service.ts` | Scan lifecycle: target binding, drafts, validations, sealing, findings, exports, and comparisons. |
| `src/store.ts` | State directory resolution, scan directories, index, atomic JSON writes, sealed-file sets. |
| `src/deep-*.ts`, `src/secure-read.ts`, `src/state-lock.ts` | Deep orchestration, isolated worker reads and cross-process locks. |
| `src/target.ts` | Target resolution, file inventory, content hashing, and language and size caps. |
| `src/git.ts` | Git revision, diff, and changed-file queries. |
| `src/tools.ts` | The 31 `codex_security_*` tool definitions and their argument schemas. |
| `src/routes.ts` | `/plugins/codex-security` HTTP routes used by the workbench. |
| `src/contracts.ts` | Finding normalization and fingerprints, coverage, SARIF, and the policy gate. |
| `src/schema.ts` | AJV validation of sealed documents against `schemas/`. |
| `src/types.ts` | Shared scan, finding, coverage, and record types. |
| `src/util.ts` | Filesystem, hashing, timestamp, and JSON helpers. |
| `src/client/index.tsx` | The workbench settings section and its fetch calls. |
| `tests/*.test.mjs` | Unit, real-host integration, and scan-regression suites. |

</details>

-----

<a id="further-exploration"></a>
## Further Exploration

- [CHANGELOG.md](CHANGELOG.md) — release history and the unreleased fixes.
- [docs/TOOLS.md](docs/TOOLS.md) — every tool's arguments, return shape, and lifecycle rule.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — host lifecycle, target binding, state and sealing, concurrency.
- [docs/ARTIFACTS.md](docs/ARTIFACTS.md) — artifact contracts for scans, findings, coverage, and manifests.
- [docs/SPEC.md](docs/SPEC.md) — product surface, configuration, storage, and workbench routes.
- [docs/VALIDATION.md](docs/VALIDATION.md) — the automated checks and package inspection commands.
- [schemas/](schemas/) — the JSON Schema contracts enforced at sealing.
- [references/](references/) — security guidance used by the scan skills.
- [examples/](examples/) — a completed scan and a legacy completed scan.
- [DeepSeek Harness package-bundle template](https://github.com/deepseek-ai/deepseek-harness/blob/master/.agents/skills/dsh-doc-writing/templates/package-bundle.md) — the document convention this README follows.
- [Apache-2.0 license](LICENSE).

-----

<a id="model-experience"></a>
## Model Experience

Indirectly, through the 31 registered tool schemas and 16 bundled skill descriptions: their names, descriptions, and argument schemas enter the model's tool and skill catalogs, and scan state otherwise reaches the model only as JSON results of tools the agent calls.

#### KV Cache effect

Activating the layer adds 31 tool definitions and 16 skill catalog entries to the prompt prefix the host builds for a session, and removing the layer removes the same text. Within a session the catalog is stable, so the added tokens belong to the cached prefix and do not grow per turn; starting, updating, and completing a scan append ordinary tool results and assistant messages after that prefix. Automatic workers also receive a focused review prompt and the verified source chunks they request.

<a id="known-limitations-and-deferred-work"></a>
## Known Limitations and Deferred Work

These limits define when the layer does not fit and what it needs from the profile around it.

- **Model review** — the host stores and validates what agents submit; it cannot prove that a model understood every file or that coverage is exhaustive.
- **Static review** — restricted workers do not build or execute target code. The configured model provider may use the network, and runtime-only weaknesses remain outside this evidence.
- **Deep budgets** — automatic mode limits workers, attempts, no-new reviews and elapsed time; it does not cap model tokens or monetary cost. Manual mode records advisory limits.
- **Local state** — cross-process coordination requires trusted local storage with reliable SQLite locks. A failed seal can leave intermediate files in a running scan.
- **Sealing is one-way** — agent artifacts can be written only while a scan is running, and `codex_security_save_artifact` refuses sealed and internal paths; triage is the only post-completion mutation, and it never changes the sealed documents.
- **Exports stay local by default** — writing outside the state directory, the process working directory, and the target root requires `allowExportOutsideWorkspace: true`; exporting into the scan storage under `repositories/` is always refused.
- **Native support for file exports** — the matching optional platform binary must be available for file export; if it is missing, file export and automatic worker source reads fail closed; manual scans and in-memory exports remain available. The binary package has no dependency install script.
- **Inventory caps bound the evidence** — `maxFiles` and `maxFileBytes` limit the reviewable inventory, unreadable files become warnings, and the snapshot digest covers only inventoried content, so files outside the caps are outside the evidence.
- **Comparison does not prove a fix** — `codex_security_compare_scans` requires completed scans with a compatible target, mode, and scope, complete coverage, and non-truncated inventories. It compares fingerprints and uniquely matched legacy identities; a missing fingerprint is not a verified fix.

<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

`npm run build` removes `lib/`, compiles the host with `tsc -p tsconfig.json`, compiles the client with `tsc -p tsconfig.client.json`, and runs `node scripts/bundle-client.mjs` to wrap `lib/client.js` for the DSH module loader. `npm test` builds first and then runs `node --test tests/*.test.mjs`; `npm run typecheck` runs both compiler projects with `--noEmit`; `npm pack --dry-run` lists the published files. Node.js 22.19 or newer is required by `engines`, and the host needs `@deepseek-ai/cordis` (~4.1.0) and `@deepseek-ai/dsh-skill` (>=0.2.2-rc.2 <0.3.0) as peer dependencies, with the pinned DSH 0.2.2-rc.2 packages in `devDependencies` backing the host integration test. The compiled `lib/` output is tracked and CI checks that a rebuild leaves it unchanged, so edit `src/` and rebuild rather than patching `lib/`. Scan state under the profile's `data/codex-security` directory is user data: `index.json` is rebuildable, `scan-manifest.json` seals each completed scan, and deleting sealed files destroys the evidence the manifest describes.

</details>
