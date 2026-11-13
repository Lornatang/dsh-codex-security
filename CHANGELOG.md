# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Declare the required DSH skill service and register loadable bundled skills.
- Validate tool arguments and JSON output through the real DSH host contract.
- Bind accurate target scopes, file contents and complete Git diffs, including untracked files.
- Require explicit review coverage and diff dispositions before sealing; reject changed targets,
  incompatible comparisons and writes to sealed artifacts.
- Serialize scan mutations, rebuild missing indexes and validate sealed JSON against the bundled schemas.

### Added

- A default-mode start tool, a diff review-item update tool and real-host regression tests.

### Changed

- Publish the plugin as the scoped npm package `@lornatang/dsh-codex-security`. The
  initial bare `dsh-codex-security@0.1.0` publish is deprecated in favour of the scoped
  name; install with `dsh plugin --profile <profile> add @lornatang/dsh-codex-security`.
- Ship the English documentation and examples with the package; align the architecture,
  tool reference and skill workflows with the implementation.

## [0.1.0] - 2026-11-13

Initial public release of the DeepSeek Harness port of the codex-security scan model.

### Added

- DSH plugin `codex-security` (`dsh-codex-security`) with a loader patch row,
  a host plugin entry point, HTTP routes under `/plugins/codex-security` and a
  **Codex Security** settings section in the web UI.
- 27 `codex_security_*` host tools covering setup/target inspection, standard,
  prompt-only and deep scan lifecycle, discovery candidates, validations, attack
  paths, artifacts, drafts, findings and triage, diff review items, export and scan
  comparison.
- Ten agent skills registered from `skills/`: `security-scan`,
  `security-diff-scan`, `deep-security-scan`, `fix-finding`, `verify-fix`,
  `triage-finding`, `threat-model`, `track-findings`,
  `resolve-dependency-alert` and `vulnerability-writeup`.
- Sealed scan contract adapted from OpenAI codex-security: `findings.json`,
  `coverage.json`, `scan-manifest.json` and `report.md`, with stable
  `csf_`/`occ_` ids and `codex-security/v1` fingerprints.
- Deep-scan orchestration with worker count, discovery-run budget,
  stop-after-no-new and time limits recorded on the scan.
- Diff scanning for pull requests, commit ranges, branches and working trees, with
  per-file review items.
- Exports in SARIF 2.1.0, JSON, CSV and Markdown, plus a `failOnSeverity`
  policy gate.
- Web workbench: status header, scan list, findings table with severity chips and
  triage state, coverage summary and export links.
- Configuration through Schemastery: `stateDir`, `maxFiles`, `maxFileBytes`,
  `defaultMode`, `failOnSeverity`, `allowExportOutsideWorkspace`,
  `maxScanAgeDays`, `deepWorkers` and `deepMaxDiscoveryRuns`.
- Documentation: README, architecture, tool reference,
  artifact contract, validation guide, and a GitHub Actions CI workflow.
