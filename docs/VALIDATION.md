# Validation

Run the automated checks from the repository root with Node.js 22.19 or later:

```bash
npm ci --no-audit --no-fund
npm run typecheck
npm test
```

`npm test` rebuilds the tracked host and client output and runs the Node test suite. The suite exercises real Cordis, DSH skill and tool registries, and the DSH tool execution pipeline without a user profile. It also covers scoped and diff targets, untracked files, snapshot changes, draft completeness, candidate concurrency, comparison guards, sealed artifacts, schema validation and index recovery.

CI runs these checks on Node 22.19 and 24. After committing any regenerated `lib/` files, `git diff --exit-code -- lib` verifies that another build is reproducible. The integration test uses the pinned DSH 0.2.2-rc.2 development packages. It does not replace a full manual DSH application or agent review.

## Package inspection

```bash
npm pack --dry-run
```

The package must include `lib/`, `cordis.patch.yml`, `skills/`, `references/`, `schemas/`, `docs/`, `examples/`, `README.md`, `CHANGELOG.md`, `LICENSE` and `NOTICE`. Source, tests and local dependencies are not published. The README and project documentation are in English.

## Optional isolated DSH check

Use a disposable DSH home rather than a working profile. Generate a tarball with `npm pack`, capture the actual filename printed by npm, and install it into a profile under that temporary home. Check that the host loads, all ten skills can be read, and the workbench routes respond. Remove the disposable home after the check. This exercise may need npm registry access to install package dependencies.

## Artifact checks

Findings, coverage and manifest documents are validated against `schemas/` by the host before sealing. The regression suite independently validates generated examples and checks the SHA-256 digest of a sealed supporting artifact. Check a complete manual review as well when changing the workflow: account for each bound diff file, compare only compatible completed scans, and verify that attempted post-completion writes fail.

A green build confirms the exercised behavior. It does not establish that an agent actually reviewed every claimed surface or that the target has no vulnerabilities.
