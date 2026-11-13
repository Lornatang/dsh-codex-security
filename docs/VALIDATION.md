# Validation and Acceptance Checks

This page describes how to validate a checkout or a release of **dsh-codex-security**:
static checks, loading the plugin into a throwaway DSH profile, and running a real scan
against a deliberately vulnerable fixture. Use it before tagging a release or when
reviewing a contribution.

All commands are written for a POSIX shell (bash or zsh) and assume the repository root as
the working directory.

## Prerequisites

| Tool | Version | Used by |
| --- | --- | --- |
| Node.js | 22.19 or newer | typecheck, build, tests, integration checks |
| npm | bundled with Node.js | dependency install, pack |
| DSH | 0.2.2-rc.2 or newer | steps 2-5 (plugin load, workbench, scans) |
| git | any recent version | diff scans, the CI git diff check |
| Network | only for `npm ci` and optional `npx` | step 1 and step 5 |

```bash
node -v          # v22.19.0 or newer
npm -v
dsh --version    # 0.2.2-rc.2 or newer
```

## 1. Static checks

CI runs the same sequence on Ubuntu 24.04 with Node.js 22.19.0 and 24 (see
`.github/workflows/ci.yml`). Run it locally first:

```bash
npm ci --no-audit --no-fund
npm run typecheck
npm run build
npm test
```

What each command does:

| Command | Action | Expected result |
| --- | --- | --- |
| `npm ci` | clean install from `package-lock.json` | `node_modules`, no audit output required |
| `npm run typecheck` | `tsc -p tsconfig.json --noEmit` and `tsc -p tsconfig.client.json --noEmit` | exit code 0, no diagnostics |
| `npm run build` | `clean` then host, client and bundle builds | `lib/` populated, `lib/client-build` removed |
| `npm test` | builds, then `node --test tests/*.test.mjs` | 6 passing tests |

`npm test` includes the build, so a green test run also proves the build works. The six
tests are:

```text
apply registers the documented tool surface and bundled skills
finding identity is stable across line moves and unique per location
policy gate fails at or above the configured severity
scan lifecycle seals findings, coverage, report and manifest
routes expose status, scan list and sealed artifacts
store recovers scans from disk when the index is missing
```

### Build output checks

```bash
test -f lib/index.js
test -f lib/constants.js
test -f lib/client.js
test -f lib/types/index.d.ts
test ! -d lib/client-build
node --input-type=module -e "import('./lib/constants.js').then((m) => console.log(m.TOOL_NAMES.length, m.SKILL_NAMES.length))"
```

The last command must print `27 10` — 27 tools and 10 skills. If it prints different
numbers, `src/constants.ts` and the bundled skills drifted apart.

### Published file audit

```bash
npm pack --dry-run
```

The tarball must contain `lib/`, `cordis.patch.yml`, `skills/`, `references/`,
`schemas/`, `README.md`, `README.zh.md`, `CHANGELOG.md`, `LICENSE` and `NOTICE`.
`docs/`, `src/` and `tests/` are intentionally not published; documentation in
`docs/` is only available in the repository.

## 2. Load the plugin in a temporary DSH profile

Never point a test install at your working profile. Create a throwaway DSH home instead.

```bash
export TEST_HOME="$(mktemp -d)"
export DSH_HOME="$TEST_HOME"
npm pack
TARBALL="$(pwd)/lornatang-lornatang-dsh-codex-security-0.1.0.tgz"
dsh plugin --profile codex-security-test add "$TARBALL"
```

Notes:

- Pass an **absolute** tarball path: DSH delegates the install to its bundled pnpm running
  inside the profile directory.
- The first `add` initializes `$DSH_HOME/profiles/codex-security-test`.
- DSH composes the package's `dsh.bundle.patch` layer automatically; you do not edit the
  profile patch by hand.

### Verify the composed configuration

```bash
dsh --profile codex-security-test --dump-config | grep -A7 codex-security
```

Expected output:

```yaml
# == dsh-codex-security
- id: codex-security
  name: @lornatang/dsh-codex-security
  config:
    maxFiles: 5000
    maxFileBytes: 1048576
    defaultMode: standard
```

If the row is missing, check that `package.json` declares
`dsh.bundle.patch: ./cordis.patch.yml` and that the file contains the
`id: codex-security` insert row.

### Boot the workbench and probe the routes

```bash
dsh web --profile codex-security-test --no-open
```

Leave it running and, from another shell, replace `PORT` with the port DSH prints:

```bash
PORT=5173
curl -s "http://127.0.0.1:$PORT/plugins/codex-security/status"
curl -s "http://127.0.0.1:$PORT/plugins/codex-security/config"
curl -s "http://127.0.0.1:$PORT/plugins/codex-security/scans?limit=5"
curl -s "http://127.0.0.1:$PORT/plugins/codex-security/findings?limit=5"
curl -s "http://127.0.0.1:$PORT/plugins/codex-security"
```

Expected results:

| Probe | Expectation |
| --- | --- |
| `/status` | `ok: true`, `name: "dsh-codex-security"`, `plugin: "codex-security"`, `version: "0.1.0"`, a `stateDir` under the test profile, scan/finding counters |
| `/config` | the nine public configuration keys with their effective values |
| `/scans`, `/findings` | `ok: true`, `total`, empty arrays on a fresh profile |
| `/` | `ok: true` plus the route index |
| unknown scan id | HTTP 404 |
| malformed triage body | HTTP 400 |

All JSON responses use `content-type: application/json; charset=utf-8`,
`cache-control: no-store` and `x-content-type-options: nosniff`. Export downloads use the
`content-disposition` attachment header instead.

### Verify the tool, skill and settings surface

- The DSH settings page shows a **Codex Security** section (order 41) with the status
  header, scan list and refresh control.
- The agent can call exactly 27 `codex_security_*` tools (list in
  [TOOLS.md](TOOLS.md)).
- Exactly 10 skills are registered: `security-scan`, `security-diff-scan`,
  `deep-security-scan`, `fix-finding`, `verify-fix`, `triage-finding`,
  `threat-model`, `track-findings`, `resolve-dependency-alert`,
  `vulnerability-writeup`.

Ask the agent directly:

```text
List every codex_security tool you can call, and every codex-security skill that is loaded.
```

### Cleanup

```bash
dsh plugin --profile codex-security-test remove @lornatang/dsh-codex-security
rm -rf "$TEST_HOME" lornatang-dsh-codex-security-0.1.0.tgz
unset TEST_HOME DSH_HOME
```

If you skipped the throwaway home and used your real one, delete
`$DSH_HOME/profiles/codex-security-test` manually.

## 3. Manual scan of a sample repository

### Create the fixture

```bash
rm -rf /tmp/codex-security-fixture
mkdir -p /tmp/codex-security-fixture
cat > /tmp/codex-security-fixture/server.mjs <<'EOF'
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function readUserFile(baseDir, name) {
  // Path traversal: name is joined without containment checks.
  return readFile(join(baseDir, name), 'utf8');
}

export function deleteProject(db, principal, projectId) {
  // Missing authorization: the project owner is never compared.
  const project = db.projects.get(projectId);
  db.projects.delete(projectId);
  return project;
}
EOF
git -C /tmp/codex-security-fixture init -q
git -C /tmp/codex-security-fixture add .
git -C /tmp/codex-security-fixture -c user.email=test@example.com -c user.name=Test commit -qm fixture
```

The fixture contains a path-traversal sink and a missing-authorization check. A correct
standard scan reports both as findings or explicitly defers them.

### Run the scan

In a DSH session with the plugin installed, either invoke the skill or ask in plain
language:

```text
Run a security scan of /tmp/codex-security-fixture and complete the scan.
```

or:

```text
$security-scan /tmp/codex-security-fixture
```

Expected tool sequence for a standard scan:

```text
codex_security_inspect_setup
codex_security_inspect_target
codex_security_start_standard_scan
codex_security_record_discovery_candidates   (deep or thorough runs)
codex_security_record_scan_draft
codex_security_complete_scan
```

`codex_security_complete_scan` returns `status: "completed"`, `sealedAt`,
`findingsCount`, `severityCounts`, `policy`, and absolute plus relative paths for
`report.md`, `findings.json`, `coverage.json`, `scan-manifest.json` and `sarif.json`.

### Locate the scan directory

```bash
STATE_DIR="$HOME/.dsh/profiles/codex-security-test/data/codex-security"
# Use $DSH_HOME instead of $HOME/.dsh when it is set; GET /plugins/codex-security/status
# also reports the effective stateDir.
find "$STATE_DIR/repositories" -maxdepth 4 -type f | sort
SCAN_DIR="$(ls -d "$STATE_DIR"/repositories/*/scans/cs_* | head -n1)"
echo "$SCAN_DIR"
```

A completed scan directory contains:

```text
scan.json
findings.json
coverage.json
scan-manifest.json
report.md
sarif.json
threat-model.md                 (optional)
checkpoints/scan-draft.json
findings/<slug>/<slug>.md       (agent-saved writeups, scan-relative)
artifacts/<path>                (agent-saved coverage receipts)
```

### Contract assertions

```bash
node --input-type=module - "$SCAN_DIR" <<'EOF'
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const dir = process.argv[2];
const load = async (name) => JSON.parse(await readFile(join(dir, name), 'utf8'));
const assert = (condition, message) => {
  if (!condition) throw new Error('FAIL: ' + message);
};

const findings = await load('findings.json');
const coverage = await load('coverage.json');
const manifest = await load('scan-manifest.json');

assert(findings.documentType === 'codex-security.findings', 'findings documentType');
assert(findings.schemaVersion === '1.0', 'findings schemaVersion');
assert(typeof findings.scanId === 'string' && findings.scanId.startsWith('cs_'), 'scanId');
assert(Array.isArray(findings.findings), 'findings array');

const ids = new Set();
for (const finding of findings.findings) {
  assert(/^csf_[a-f0-9]{24}$/.test(finding.findingId), 'findingId pattern');
  assert(/^occ_[a-f0-9]{24}$/.test(finding.occurrenceId), 'occurrenceId pattern');
  assert(finding.identity && typeof finding.identity.anchor === 'string', 'anchor');
  assert(finding.fingerprints.algorithm === 'codex-security/v1', 'fingerprint algorithm');
  assert(/^codex-security\/v1:sha256:[a-f0-9]{64}$/.test(finding.fingerprints.primary), 'fingerprint pattern');
  assert(['critical', 'high', 'medium', 'low', 'informational'].includes(finding.severity.level), 'severity');
  assert(finding.locations.length >= 1, 'locations');
  assert(!finding.locations[0].path.startsWith('/'), 'relative path');
  ids.add(finding.findingId);
}
assert(ids.size === findings.findings.length, 'unique finding ids');

assert(coverage.documentType === 'codex-security.coverage', 'coverage documentType');
assert(Array.isArray(coverage.surfaces) && coverage.surfaces.length >= 1, 'surfaces');
for (const surface of coverage.surfaces) {
  assert(typeof surface.label === 'string' && surface.label.length > 0, 'surface label');
  assert(['reported', 'no_issue_found', 'rejected', 'not_applicable', 'needs_follow_up'].includes(surface.disposition), 'disposition');
  for (const receipt of surface.receiptRefs || []) {
    assert(receipt.startsWith('artifacts/'), 'receiptRefs under artifacts/: ' + receipt);
  }
}

assert(manifest.documentType === 'codex-security.scan-manifest', 'manifest documentType');
assert(manifest.scan.status === 'completed', 'manifest status');
assert(manifest.scan.producer.name === '@lornatang/dsh-codex-security', 'producer name');
assert(manifest.scan.producer.version === '0.1.0', 'producer version');
assert(manifest.scan.findingsRef === 'findings.json', 'findingsRef');
assert(manifest.scan.sealedAt >= manifest.scan.completedAt, 'seal timestamps');

const sealed = manifest.scan.artifacts.map((entry) => entry.path);
assert(sealed.filter((path) => path === 'findings.json').length === 1, 'findings.json sealed once');
assert(sealed.includes('coverage.json'), 'coverage.json sealed');
assert(sealed.includes('report.md'), 'report.md sealed');
assert(sealed.includes('sarif.json'), 'sarif.json sealed');

for (const entry of manifest.scan.artifacts) {
  const bytes = await readFile(join(dir, entry.path));
  const digest = createHash('sha256').update(bytes).digest('hex');
  assert(digest === entry.sha256, 'sha256 mismatch: ' + entry.path);
}

console.log('OK: ' + findings.findings.length + ' findings, ' + sealed.length + ' sealed artifacts');
EOF
```

The script exits non-zero on the first violation. A passing run prints
`OK: N findings, M sealed artifacts`. The sealed-file hashes are the authoritative link
between the manifest and every other artifact — do not edit sealed files.

### SARIF checks

```bash
node --input-type=module - "$SCAN_DIR/sarif.json" <<'EOF'
import { readFile } from 'node:fs/promises';

const sarif = JSON.parse(await readFile(process.argv[2], 'utf8'));
const assert = (condition, message) => {
  if (!condition) throw new Error('FAIL: ' + message);
};

assert(sarif.version === '2.1.0', 'SARIF version');
assert(sarif.runs.length === 1, 'one run');
assert(sarif.runs[0].tool.driver.name === 'codex-security', 'driver name');

const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((rule) => rule.id));
for (const result of sarif.runs[0].results) {
  assert(ruleIds.has(result.ruleId), 'result ruleId declared: ' + result.ruleId);
  assert(['error', 'warning', 'note'].includes(result.level), 'result level');
  assert(result.locations[0].physicalLocation.artifactLocation.uriBaseId === '%SRCROOT%', 'uriBaseId');
  assert(typeof result.fingerprints['codex-security/v1'] === 'string', 'fingerprint');
  assert(typeof result.properties['security-severity'] === 'string', 'security-severity');
}
console.log('OK: ' + sarif.runs[0].results.length + ' SARIF results');
EOF
```

### Negative checks

| Action | Expected error |
| --- | --- |
| `complete_scan` without a recorded draft | `codex-security: no draft recorded; call codex_security_record_scan_draft before completing the scan` |
| `complete_scan` twice | `codex-security: scan already completed: <id>` |
| `save_artifact` to `findings.json` | `codex-security: cannot overwrite sealed artifact path: findings.json` |
| `save_artifact` with `../escape.md` | path rejected |
| `set_finding_triage` with an unknown status | validation error naming the allowed statuses |
| `export_findings` to a path outside the workspace with `allowExportOutsideWorkspace: false` | `codex-security: refusing to write outside the workspace/state dir; ...` |

## 4. Export, triage, comparison and diff review

### Export formats

In the same session ask:

```text
Export the findings of <scanId> as sarif, json, csv and markdown.
```

`codex_security_export_findings` writes to `<stateDir>/exports/` by default. Inspect:

```bash
EXPORT_DIR="$STATE_DIR/exports"
ls -l "$EXPORT_DIR"
head -n 2 "$EXPORT_DIR"/*.csv          # header: finding_id,occurrence_id,severity,...
head -n 5 "$EXPORT_DIR"/*.md           # "# Security review: ..."
```

File names are `<scanId>.json`, `<scanId>.sarif.json`, `<scanId>.csv` and
`<scanId>.md`. The JSON export is the sealed `findings.json`; the SARIF export is the
sealed `sarif.json`; Markdown is the sealed `report.md`.

### Triage persistence

```text
Mark finding <findingId> as false_positive with the note "fixture-only code".
```

Then check `codex_security_list_findings` with `status: "false_positive"` and
`codex_security_get_scan`, which includes the triage map. Triage state is mutable local
state and does not change sealed documents.

### Fix verification with compare_scans

1. Fix the fixture: add `resolve()` containment in `readUserFile` and an owner check in
   `deleteProject`.
2. Run a second standard scan of the same directory.
3. Ask: `Compare scans <baseScanId> and <headScanId>.`

Expected: `compareScans.closed` includes the fixed findings, `open` and `new` are empty
or contain only intentionally introduced items. Matching is by primary fingerprint, so
line moves alone do not count as closed/new.

### Diff review items

Prepare review items only for diff scans. In a git checkout:

```text
Start a diff scan of /tmp/codex-security-fixture against HEAD~1, then prepare the review
items and list them.
```

Expected: `prepare_review_items` returns one item per changed file (added, modified,
deleted, renamed), `list_review_items` reports their statuses, and every changed file ends
`reviewed`, `no_issue_found`, `rejected`, `not_applicable` or
`needs_follow_up`. Calling review tools on a non-diff scan returns
`codex-security: review items require a diff scan (start with diffTarget or workingTree)`.

### Cleanup

```bash
rm -rf /tmp/codex-security-fixture
```

## 5. Schema validation (optional)

The JSON Schemas in `schemas/` are draft 2020-12. With network access:

```bash
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s schemas/findings.schema.json -d "$SCAN_DIR/findings.json"
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s schemas/coverage.schema.json -d "$SCAN_DIR/coverage.json"
npx --yes ajv-cli@5 validate --spec=draft2020 \
  -s schemas/scan-manifest.schema.json -d "$SCAN_DIR/scan-manifest.json"
```

Known strictness differences between the upstream schemas and this plugin's output are
listed in [ARTIFACTS.md](ARTIFACTS.md) (**Schema strictness notes**). Expect a few
diagnostics there rather than editing sealed files; the plugin output is internally
consistent and its manifest hashes are authoritative.

## 6. Security review checklist for the plugin itself

Use this when reviewing changes to the host, tools, routes or skills.

| Check | Verify | Expected |
| --- | --- | --- |
| Target is read-only | `grep -RIn "writeFile\|writeFileAtomic\|rename(" src` | only `src/util.ts` and `src/store.ts` write files, and only under the state directory |
| No target execution | `grep -RIn "execFile\|spawn(\|exec(" src` | `execFile` only in `src/git.ts`, invoking read-only git queries |
| No network from the host | `grep -RIn "fetch(\|http.request\|https.request\|net.connect" src` | `fetch` only in `src/client/index.tsx`, same-origin plugin routes |
| Path containment | `sanitizeRelative` and `joinWithin` on artifact and export paths; try `../` and absolute paths | rejected with a `codex-security:` error |
| Sealed documents protected | `save_artifact` to `scan.json`, `findings.json`, `coverage.json`, `scan-manifest.json`, `sarif.json`, `report.md` or `threat-model.md` | `cannot overwrite sealed artifact path` |
| Export confinement | default `allowExportOutsideWorkspace: false` | outside paths refused |
| State permissions | `ensureDir` uses mode `0700` | scan data not world-readable |
| Prompt injection | read a tool description and a skill | both contain the untrusted-data rule; the sealed report has a Limitations section |
| Secret handling | read the skills' secret rule | secrets are redacted to a prefix plus length, with only path and line cited; never echoed |
| Client XSS | `grep -RIn "dangerouslySetInnerHTML\|innerHTML" src/client` | no matches; React escapes rendered values |
| HTTP hardening | inspect `src/routes.ts` | JSON only, 1 MiB body limit, `no-store`, `nosniff`, 404/400 mapping, attachment header only for exports |
| Dependencies | `package.json` | runtime dependency only `@deepseek-ai/schemastery`; `@deepseek-ai/cordis` is a peer; no postinstall script |
| Licensing | `LICENSE` and `NOTICE` | Apache-2.0, NOTICE credits OpenAI codex-security and lists what was adapted |
| No auto-patching | `src/` | no patch application code; proposed patches are only saved as artifacts |

## 7. Release checklist

- [ ] `npm run typecheck`, `npm run build` and `npm test` are green on the release commit.
- [ ] `node --input-type=module -e "import('./lib/constants.js').then((m) => console.log(m.VERSION))"`
      matches `package.json` version.
- [ ] `CHANGELOG.md` has an entry for the version.
- [ ] `npm pack --dry-run` lists the expected files (no `src/`, no `docs/`, no
      `tests/`).
- [ ] Temporary-profile install from the packed tarball loads the loader row, the 27 tools,
      the 10 skills and the settings section.
- [ ] A manual scan on the fixture completes and passes the contract assertions above.
- [ ] No credentials, tokens or private paths are committed.
- [ ] `LICENSE` and `NOTICE` are unchanged and still credit OpenAI codex-security.

## 8. Known expected deviations

These are known and documented; do not treat them as validation failures:

- `examples/` contains upstream-shaped sample documents, not verbatim plugin output
  (different producer string, scan ids and artifact list). See
  [ARTIFACTS.md](ARTIFACTS.md).
- The upstream draft and common schemas declare `scanId` as a UUID, while this plugin uses
  `cs_` ids; the manifest `scope.artifactsReviewed` field is a number here and a string
  list upstream; `scope.context` may be `null`.
- `package.json` declares `engines.dsh: "*"` while the documented requirement is DSH
  0.2.2-rc.2 or newer; the requirement is enforced by documentation, not by npm.
- Scan state is serialized within one DSH process only. Sharing a state directory between
  two running DSH processes is unsupported; see
  [ARCHITECTURE.md](ARCHITECTURE.md).
- The CI `git diff --exit-code -- lib` step is a guard against accidentally tracked build
  output; `.gitignore` ignores `lib/`, so it passes on a clean checkout.
