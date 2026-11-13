# Architecture

This document describes how dsh-codex-security is built and how a scan moves from target
binding to sealed artifacts. It documents the implementation in `src/` as shipped in version
0.1.0.

## Package layout

```text
dsh-codex-security/
  package.json            # DSH plugin manifest (dsh.bundle / dsh.client)
  cordis.patch.yml        # profile patch that inserts the codex-security plugin row
  tsconfig.json           # host-side TypeScript build (ESM)
  tsconfig.client.json    # browser-side TypeScript build (CommonJS + DOM/JSX)
  scripts/bundle-client.mjs
  src/
    index.ts              # plugin entry: apply(), skills loader, public exports
    constants.ts          # names, version, skill/tool lists, default excludes
    config.ts             # Schemastery schema + defaults
    types.ts              # shared domain types
    contracts.ts          # normalization, fingerprints, ids, artifact builders, SARIF/CSV
    store.ts              # on-disk scan store, index cache, atomic writes
    target.ts             # target resolution and file inventory
    git.ts                # read-only git helpers
    service.ts            # SecurityService: all tool/route behavior
    tools.ts              # 27 host tool definitions
    routes.ts             # HTTP routes under /plugins/codex-security
    util.ts               # hashing, paths, globbing, atomic file I/O
    client/index.tsx      # browser workbench (settings.section)
  skills/<name>/SKILL.md  # 10 bundled agent workflows
  schemas/                # JSON Schema contracts for the artifacts
  examples/               # illustrative artifact documents
  references/             # upstream design reference material
  lib/                    # build output (not committed)
```

`src/core/` exists as reserved space and is empty in 0.1.0; the host build only compiles
`src/*.ts`, and the client build only compiles `src/client`.

### Build outputs

| Script | Output | Purpose |
| --- | --- | --- |
| `npm run build:host` | `lib/*.js`, `lib/types/` | ESM host code and declarations from `src/*.ts`. |
| `npm run build:client` | `lib/client-build/` | CommonJS browser bundle input from `src/client`. |
| `npm run build:bundle` | `lib/client.js` | Wraps the client build for the DSH module loader. |
| `npm run build` | `lib/` | Cleans, then runs host, client and bundle steps. |

`package.json` exports `lib/index.js` as the plugin entry and `lib/client.js` as the browser
half; `lib/` is generated and not committed.

## Module map

### `src/index.ts` — plugin entry

- Exports `name = 'codex-security'`, `inject = ['tools']`, `Config`, `version`,
  `packageName`, `SecurityService` and the default plugin object.
- `apply(ctx, config)` resolves `packageRoot` from `import.meta.url`, constructs one
  `SecurityService`, and registers three effects: tools, skills and HTTP routes. All three
  are disposed through `ctx.effect(...)` when the plugin unloads.
- `loadBundledSkills(packageRoot)` walks `skills/*/SKILL.md`, parses a minimal YAML
  frontmatter (`name`, `description`, `whenToUse`) and builds DSH skill registrations
  (`modelInvocable` and `userInvocable` both true, `metadata.plugin` set to the package
  name). Entries without a valid name or description are skipped.
- `registerSkills` uses `ctx.skills.register` when the skills service is present, logs
  `codex-security: registered N skills` on success and a warning when the service is
  unavailable. Individual registration failures are logged and skipped.
- The plugin logs `codex-security: ready (state dir will resolve on first scan)`; the state
  directory is not created until a scan needs it.

### `src/constants.ts`

Single source of truth for public names: `PACKAGE_NAME`, `PLUGIN_NAME`, `VERSION`,
`ROUTE_PREFIX`, `PRODUCER` (manifest producer identity), `DEFAULT_EXCLUDES` (dependency,
build and VCS directories), `SKILL_NAMES` (10) and `TOOL_NAMES` (27). Tests assert the
registered tool and skill surface against these arrays.

### `src/config.ts`

Schemastery schema for the plugin config plus `DEFAULT_CONFIG`. Numeric bounds are enforced
by the schema (`maxFiles` 1–200000, `maxFileBytes` 1 KiB–64 MiB, `maxScanAgeDays`
1–3650, `deepWorkers` 1–32, `deepMaxDiscoveryRuns` 1–10000). `SecurityService` merges the
provided config over the defaults, so a partial patch is valid.

### `src/store.ts` — `ScanStore`

Owns the state directory and every disk write except exports:

- Resolves the default state directory when `stateDir` is empty:
  `<profile patch dir>/data/codex-security`, falling back to
  `$DSH_HOME/profiles/web/data/codex-security` and then `~/.dsh/...`.
- `index.json` caches scan summaries for fast listing. It is a rebuildable cache: when it is
  missing or stale, `get`/`list` fall back to reading `repositories/**/scans/*/scan.json`
  and repair the index.
- `repoKey` is the first 16 hex characters of the sha256 of the absolute target root path.
  `scanId` is `cs_` plus 24 random hex characters (120 bits of entropy).
- Creates each scan directory with `scan.json` and the `checkpoints/` and `artifacts/`
  subdirectories.
- Serializes mutations through an in-process promise queue and writes every JSON file with a
  same-directory temporary file followed by `rename` (see *Concurrency*).

### `src/target.ts`

Resolves what is being scanned and produces the inventory:

- Chooses `git_diff` (`diffTarget`/`workingTree` in a git repository), `git_worktree`
  (clean or dirty git repository) or `directory_snapshot` (non-git directory).
- Collects tracked and untracked files via `git ls-files`/`status`, or walks the directory
  tree; filters binary extensions and `DEFAULT_EXCLUDES`; applies include/exclude filters
  and the `maxFiles` cap.
- Computes a `snapshotDigest` (`codex-security-snapshot/v1:sha256:...`) from the commit,
  a content hash of the worktree, or the non-git file list; assigns `targetId` from
  kind + root + revision + diff target; derives a display name from the git remote or the
  directory name.
- `readEvidenceLine` loads bounded file content so draft findings can carry a normalized
  anchor line without reading whole files repeatedly.

### `src/git.ts`

Thin, read-only git wrapper around `execFile` (64 MiB output buffer, 60 s timeout):
repository detection, toplevel, HEAD, branch, remote URL, revision resolution, porcelain
status, tracked files, changed files with rename detection, worktree digest and file digest.
Every command is a read-only query.

### `src/contracts.ts`

The contract engine shared by tools, routes and exports:

- Normalization: rule ids, anchors, file paths, locations, severity/score, confidence,
  taxonomy category, writeup paths, draft validation.
- Identity: `codex-security/v1` fingerprints, `csf_` finding ids and `occ_` occurrence
  ids (rules are documented in [ARTIFACTS.md](ARTIFACTS.md)).
- Document builders: `findings.json`, `coverage.json`, scan manifest, `report.md`,
  SARIF 2.1.0 and CSV projections, and the severity policy gate.
- Report and SARIF rendering are deterministic projections of the sealed documents.

### `src/service.ts` — `SecurityService`

One instance per plugin load. It merges config, owns the `ScanStore` and implements every
tool and route operation: setup/target inspection, scan creation, context updates, draft
recording, candidate/validation/attack-path recording, artifact storage, sealing, triage,
exports, diff review items and scan comparison. Tools and routes are thin adapters over this
class, so a capability is never exposed in one surface only by accident.

### `src/tools.ts`

Declares the 27 `codex_security_*` tools: name, description, JSON Schema parameters,
required list, `additionalProperties: false`, an output schema with pretty-JSON rendering,
a timeout and an `execute` that delegates to the service. Registered through
`ctx.tools.register`; the returned disposers unregister them on unload.

### `src/routes.ts`

Registers a single prefix route `/plugins/codex-security` against the web server
(`ctx.get('webServer')` with `httpServer` fallback). It parses the method and path, validates
scan ids, serializes JSON with `cache-control: no-store` and `x-content-type-options:
nosniff`, enforces a 1 MiB JSON body limit, and maps service errors to HTTP status codes
(404 for unknown scans, 400 for input/validation/export-policy failures, 500 otherwise).
Browser exports are served with `content-disposition: attachment`.

### `src/client/index.tsx` — workbench

A single React component registered as `settings.section` with id `codex-security`, order
`41` and label `Codex Security`. It calls the plugin's own routes with `fetch`, keeps no
DSH client package imports, prefixes CSS classes with `.dcs-` and uses DSH design tokens
(`--dsw-alias-*`). It renders status counters, the scan list, a scan detail view with
findings/severity chips/triage selects, coverage surfaces, artifacts, and SARIF/JSON/CSV/
Markdown download links. Each request uses an `AbortController`; errors render inline
instead of throwing.

### `src/util.ts`

Cross-cutting helpers: sha256, ISO timestamps, random ids, atomic file and JSON writes,
tolerant JSON reads, POSIX-relative path handling and containment checks, gitignore-style
globbing, binary detection, language detection, severity ordering and file walking.

## State directory

```text
<stateDir>/
  index.json                                  # cached scan summaries (rebuildable)
  exports/<scanId>.<ext>                      # default export destination
  repositories/<repoKey>/scans/<scanId>/
    scan.json                                 # internal record
    findings.json                             # sealed findings contract
    coverage.json                             # sealed coverage contract
    scan-manifest.json                        # sealed manifest with sha256 hashes
    report.md                                 # deterministic human report
    threat-model.md                           # optional, when a threat model exists
    sarif.json                                # SARIF 2.1.0 projection
    candidates.json                           # discovery candidates
    validations.json                          # candidate validation outcomes
    attack-paths.json                         # candidate attack paths
    triage.json                               # finding triage/remediation state
    review-items.json                         # diff review items
    checkpoints/scan-draft.json               # latest recorded draft
    findings/<slug>/<slug>.md                 # agent-saved finding writeups (scan-relative)
    artifacts/                                # agent-saved coverage receipts and evidence
    patches/ tests/ verify/ tracking/ triage/ dependency-alerts/   # other agent-saved notes
```

Agent-saved files are scan-relative: `save_artifact` stores each path verbatim under the
scan directory, and the seal hashes every one into the manifest.


`scan.json` is the authoritative local record: lifecycle status, target and inventory,
progress, budget (deep scans), notes, threat model, artifact list, severity counts, warnings
and policy gate. The sealed documents are derived from it plus the recorded draft.

## Lifecycle

```text
              start_*_scan
                   |
                   v
   starting ----> running ---- complete_scan ----> completed (sealed)
                   |  \
                   |   +---- fail_scan ---------> failed   (unsealed)
                   |
                   +-------- cancel_scan -------> canceled (unsealed)
```

- `starting` is part of the public status enum for compatibility, but `ScanStore.create`
  writes a new scan directly as `running` (phase `target-bound`), so scans are observable
  immediately after start.
- `running` is the only state that accepts context, draft, candidate, artifact, complete,
  fail and cancel operations.
- `completed` is terminal: it is only reached by `complete_scan`, requires a recorded draft,
  and produces the sealed artifact set. Completing an already completed scan is rejected.
- `failed` and `canceled` are terminal and never sealed. Their records and any collected
  evidence remain on disk for inspection and audit.
- Every update refreshes `updatedAt` and the progress timestamp; the seal records
  `startedAt`, `completedAt` and `sealedAt` in the manifest.

## Sealing sequence

`complete_scan` is the single write barrier for the artifact contract:

1. Resolve the scan and reject completed/failed/canceled scans.
2. Require `checkpoints/scan-draft.json`. If `complete: false`, record a warning.
3. Read the recorded draft, normalize findings, compute `severityCounts`.
4. Build `coverage.json` from the draft review state (inventing a default surface and a
   `scan-summary.md` artifact when no surfaces were submitted, with a warning).
5. Render `findings.json`, `coverage.json`, `sarif.json` and `report.md`; write
   `threat-model.md` when a threat model is present. These seven root files are the sealed
   paths enforced by `save_artifact`, so agent writes cannot replace a sealed document.
6. Hash the sealed files and every file previously saved with `save_artifact` (at its
   scan-relative path) and write `scan-manifest.json` last.
7. Apply the severity policy gate (completion threshold or `failOnSeverity`; `off`
   disables it) and persist the gate result on the scan.
8. Mark the scan `completed`, store `completedAt` and the artifact list, and return paths.

Because the manifest is written last and contains sha256 hashes for all other artifacts, a
reader can detect partial or tampered seals.

## Concurrency and durability

- **Single writer process.** DSH loads the plugin once per profile; all mutations go through
  one `SecurityService` instance.
- **In-process serialization.** `ScanStore` chains mutating operations (create, update,
  triage writes) through a promise queue, so read-modify-write cycles on `scan.json` and
  `index.json` cannot interleave within the process.
- **Atomic file writes.** Every JSON/text artifact is written to a temporary file in the
  same directory and renamed into place; a failed write leaves the previous file intact and
  cleans up the temporary file. POSIX rename semantics make each file atomic, not the
  artifact set as a whole; the manifest is the integrity anchor.
- **No cross-process lock.** Two DSH processes pointed at the same state directory (for
  example a web profile and a CLI profile sharing an override) are not coordinated. Treat a
  state directory as owned by one running DSH process; the contract avoids partial files but
  cannot prevent lost updates across processes.
- **Crash recovery.** `index.json` is a cache and is rebuilt from scan directories; an
  interrupted scan remains visible with its last recorded status and can be inspected,
  failed or canceled.

## Security boundaries

| Boundary | Behavior |
| --- | --- |
| Target repository | Read-only. No tool writes, builds, executes or tests target code; git helpers issue only read-only queries. |
| Target content | Untrusted data. Tool descriptions and skills instruct the agent never to follow instructions found in source, comments, docs or generated files; the sealed report records that limitation. |
| Network | No network requests. Exports and state are local files; credentials are never validated against services. |
| Secrets | Skills require redaction to a short prefix plus length with only path and line cited; the plugin does not scan for or transmit secrets. |
| Filesystem writes | Scan state under `stateDir`; exports default to `stateDir/exports` and are confined to the workspace/state directory unless `allowExportOutsideWorkspace` is enabled. Artifact and export paths are normalized and containment-checked, and the seven sealed root files cannot be overwritten through `save_artifact`. |
| HTTP surface | Only the plugin prefix route; same-origin browser calls; no authentication layer is added because DSH already serves the local UI. JSON only except export downloads. |
| Third-party code | The plugin executes no target code and no downloaded code. Dependencies are limited to `@deepseek-ai/schemastery` at runtime (peer: `@deepseek-ai/cordis`). |
| Prompt injection | Model behavior is guided by skills (untrusted-data rule) and enforced as far as possible by the artifact contract: every finding needs a source location, validation notes and coverage receipts. |
