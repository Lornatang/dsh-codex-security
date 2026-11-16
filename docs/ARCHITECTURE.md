# Architecture

The package is a DSH host plugin with a separately compiled web client. Its scan service records agent reviews; automatic Deep coordinates independent DSH model workers and seals their validated results.

## Repository layout

```text
package.json, package-lock.json  Package metadata and locked dependencies
cordis.patch.yml                DSH bundle entry
src/index.ts                    Host entry and bundled-skill registration
src/config.ts, constants.ts     Configuration and public names
src/target.ts, git.ts           Target binding, inventory and Git queries
src/service.ts, store.ts        Scan operations, lifecycle and persistence
src/deep-*.ts, secure-read.ts   Deep coordinator, worker isolation and source binding
src/state-lock.ts               SQLite cross-process locks
src/contracts.ts, schema.ts     Artifact construction and schema validation
src/tools.ts, routes.ts         Agent tools and HTTP routes
src/client/index.tsx            Workbench settings section
skills/                         Sixteen agent workflows
schemas/                        JSON Schema contracts
references/                     Adapted reference material
examples/                       Illustrative artifacts
scripts/                        Client bundling
lib/                            Generated host/client output, committed for distribution
tests/                          Node tests and DSH host integration tests
docs/                           Project documentation
```

The host build emits ESM and declarations to `lib/`; the client build emits CommonJS and wraps it in the DSH module loader format. `npm test` rebuilds both. CI checks that a rebuild leaves the tracked `lib/` files unchanged. The npm package includes `lib`, the DSH patch, skills, schemas, references, documentation and examples; it excludes source and tests.

## Host lifecycle

The entry exports a default plugin object and named `name`, `inject`, `Config` and `apply`. Cordis must inject both `tools` and `skills` before `apply` runs. The plugin registers its tools, 16 skills with `source: bundled`, and optional HTTP routes in disposal-aware effects. The host adapter validates tool inputs and returns lossless JSON values.

## Target binding

A target must be an existing directory. Git subdirectory targets remain restricted to that subdirectory; non-Git include paths also match descendants. A diff scan binds the resolved base and head, scope and complete changed-file list at creation. Working-tree diffs include staged, unstaged and untracked files; revision-only diffs are bound to immutable Git revisions.

A snapshot digest covers the bound revision and diff list, plus the contents of inventoried reviewable files for worktree and directory scans. Files are streamed to the hash; missing or unreadable files are recorded as warnings. The inventory cap and default exclusions limit what the digest covers. Completion re-resolves the target and rejects a changed digest.

## State and sealing

State lives in `<stateDir>/repositories/<repoKey>/scans/<scanId>/`; `repoKey` is derived from the canonical target root and the scan ID is `cs_` plus 24 hex characters. `scan.json` records state, scope, inventory, progress and the bound diff list. `index.json` is a rebuildable list cache. Checkpoints, candidates, validations, attack paths and review items are stored alongside it.

A scan starts as `running` and may become `completed`, `failed` or `canceled`. Completion requires an explicit `complete: true` draft, at least one coverage surface, a disposition for each candidate, a disposition for every bound diff item, and an unchanged target. A deferred candidate must also be represented in coverage. Findings, coverage and manifest documents are validated against the bundled schemas before the seal is accepted.

The manifest hashes `findings.json`, `coverage.json`, `report.md`, `sarif.json`, an optional threat model and every agent-saved supporting artifact. Artifacts cannot be written after the scan leaves `running`, and exports cannot target scan storage. Triage is intentionally separate from the seal and can be updated after completion.

Comparison requires completed scans with compatible target, mode and scope, complete coverage and non-truncated inventories. It compares fingerprints and uniquely matched legacy identities; a reviewer must verify the source before declaring a fix.

## Concurrency and limits

A per-scan queue and SQLite OS-backed locks serialize read-modify-write operations across processes. A separate global lock protects index writes, and a campaign lock admits only one live coordinator. Lock databases persist and are released by the OS after a process exits; the trusted state directory must use a local filesystem with reliable SQLite locking. Individual JSON files use same-directory atomic replacement, not a multi-file transaction. A failed seal can leave intermediate files, but completed status is recorded only after the manifest is written.

The HTTP routes and web workbench share the same service. Export paths outside the workspace or state directory require explicit configuration. The application treats target content as untrusted, but it cannot guarantee that an agent follows a skill or that the submitted coverage is exhaustive.

## Automatic Deep coordination

A durable journal holds the immutable target and per-file digests, deadline, run attempts and hashed recovery claim. A local fresh-context `spawn` activation uses a dedicated persistent preset whose guard permits only bounded source reads and structured output. Reads use pinned handles, verify content hashes and count coverage only after the model-facing output is accepted; symlinked source components are rejected. One complete worker must receive every bound file before a zero-finding result can be sealed. Conflicting findings and failed or interrupted workers remain visible as partial coverage. Recovery needs the original live session or the returned claim; it reconciles saved child results and counts interrupted attempts. The workflow has no hard token or monetary cap.
