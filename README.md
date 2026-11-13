# dsh-codex-security

A security review workbench for DeepSeek Harness. It records agent-led static
reviews, findings and coverage, and presents the results in the DSH Web UI.
The scan and artifact model is adapted from [OpenAI codex-security](https://github.com/openai/codex-security);
this is an independent community project.

**Requires:** Node.js 22.19+ and a DSH profile with the `tools` and `skills`
services. The integration has been tested with DSH 0.2.2-rc.2 and Desktop
0.2.2-rc.3.

## Install

```bash
dsh plugin --profile web add github:Lornatang/dsh-codex-security
```

Restart DSH, or start it with `dsh web --no-open`. For another profile, replace
`web` with its name; use `desktop` for DSH Desktop. To update, run the same
install command and restart DSH.

The published [npm package](https://www.npmjs.com/package/@lornatang/dsh-codex-security)
at version 0.1.0 predates the startup and scan fixes in the 0.1.1 source. Use
the GitHub source above until a release containing those fixes is published.
To remove the plugin:

```bash
dsh plugin --profile web remove @lornatang/dsh-codex-security
```

## Configuration

Edit `~/.dsh/profiles/web/cordis.patch.yml` (or use `$DSH_HOME` in place of
`~/.dsh`) and add or edit the `codex-security` entry:

```yaml
- id: codex-security
  config:
    defaultMode: standard
    failOnSeverity: high
```

Restart DSH after changes. For a different profile, replace `web` in the path
with that profile's name.

| Option | Default | Purpose |
| --- | --- | --- |
| `stateDir` | empty | Scan storage override; empty uses the profile data directory. |
| `maxFiles` | `5000` | Maximum reviewable files included in the inventory. |
| `maxFileBytes` | `1048576` | Maximum bytes read to derive an evidence line; snapshot hashes stream file contents. |
| `defaultMode` | `standard` | Default for `codex_security_start_scan`: `standard`, `prompt-only` or `deep`. |
| `failOnSeverity` | `high` | Severity threshold recorded in the policy result; `off` disables it. |
| `allowExportOutsideWorkspace` | `false` | Permit explicit exports outside the workspace and state directory. |
| `maxScanAgeDays` | `30` | Age threshold for the workbench warning; it does not delete scans. |
| `deepWorkers` | `4` | Default worker budget recorded for a deep scan. |
| `deepMaxDiscoveryRuns` | `40` | Default discovery-run budget recorded for a deep scan. |

## Security scans

Open a repository in DSH and ask the agent to run a security scan, or invoke
`$security-scan`. The agent inspects the target, records findings and coverage,
and completes the scan. Review the result in **Settings > Codex Security** or
export it with `codex_security_export_findings`.

Use `$security-diff-scan` for a Git change and `$deep-security-scan` for an
agent-driven, multi-pass review. Diff scans accept `diffTarget`, `workingTree`,
or both. The working-tree option includes staged, unstaged and untracked files;
a revision-only diff is bound to immutable Git revisions.

The plugin provides 29 `codex_security_*` tools and 10 bundled skills. See the
[tool reference](docs/TOOLS.md) for arguments and [skills](skills/README.md) for
the workflows. Deep scans record worker and discovery budgets; the host does
not launch workers or enforce those budgets itself.

Each scan is stored under `<stateDir>/repositories/<repoKey>/scans/<scanId>/`.
A completed scan includes findings, coverage, a report, SARIF and a manifest
with SHA-256 hashes. The host requires a complete draft, explicit coverage and
candidate dispositions before sealing; diff scans also require a disposition
for each bound file. It rejects changed targets and validates the sealed JSON
against the bundled schemas. Sealed artifacts cannot be modified, while triage
records remain editable. See [artifact contracts](docs/ARTIFACTS.md) and
[examples](examples) for the formats.

Completed scans can be compared only when their target, mode, scope and coverage
are compatible. A disappeared fingerprint is a comparison result, not proof of
a fix. Snapshot hashing covers inventoried files and the bound diff list;
truncation and unreadable files are reported as limitations.

The plugin does not build, run or test target files. Its skills instruct the
agent to treat repository content as untrusted and redact secrets, but the host
cannot guarantee that an agent follows those instructions or that a review is
exhaustive. Scan data stays in the configured state directory; explicit exports
can be written to another permitted location. Sharing a state directory between
multiple DSH processes is unsupported.

## Troubleshooting

- **Plugin is not active:** Check that the installed and running profiles match,
  restart DSH, and verify that both `tools` and `skills` services are available.
- **Completion is rejected:** Finish the draft, account for coverage and
  candidates, resolve each diff review item, and start a new scan if the target
  changed after binding.
- **Comparison is rejected:** Use completed scans of the same target, mode and
  scope with comparable, non-deferred coverage.
- **Export is rejected:** Choose an allowed path outside scan storage or enable
  `allowExportOutsideWorkspace` for an explicit external export.

For development and validation, see [architecture](docs/ARCHITECTURE.md),
[specification](docs/SPEC.md) and [validation](docs/VALIDATION.md). The package
also includes the artifact [schemas](schemas) and workflow [references](references).

[Apache-2.0](LICENSE); see [NOTICE](NOTICE) for attribution and adaptation details.
