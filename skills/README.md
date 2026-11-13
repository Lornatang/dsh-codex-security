# Codex Security Skills

This directory contains the ten agent skills that ship with the Codex Security plugin for DeepSeek Harness. The plugin discovers every `skills/<name>/SKILL.md` when it starts and registers the skill automatically: there is nothing to install, enable, clone, or import, and no external command-line tool, service, database, or desktop application is required. A skill is loaded when the user selects it in the harness or when the request clearly matches its description; its instructions then guide the agent through the plugin's scan tools.

## The ten skills

| Skill | Use it when | Main tools |
| --- | --- | --- |
| `security-scan` | The user wants a normal security review of a repository, directory, or set of files. | `codex_security_inspect_target`, `codex_security_start_standard_scan`, `codex_security_record_scan_draft`, `codex_security_complete_scan` |
| `security-diff-scan` | The user wants a pull request, commit range, branch, patch, or working tree reviewed and every changed text file accounted for. | `codex_security_prepare_review_items`, `codex_security_list_review_items`, `codex_security_record_scan_draft` |
| `deep-security-scan` | The user wants an exhaustive or multi-pass audit with explicit worker and time budgets, especially when variants could hide from a single pass. | `codex_security_start_deep_scan`, `subagent`, `codex_security_record_candidate_validations`, `codex_security_complete_scan` |
| `fix-finding` | The user wants a minimal patch and static test plan for one confirmed finding, without modifying the target repository. | `codex_security_list_findings`, `codex_security_set_finding_remediation`, `codex_security_save_artifact` |
| `verify-fix` | The user wants to know whether an applied fix actually closes a finding, using a fresh scan and a scan comparison. | `codex_security_start_standard_scan`, `codex_security_compare_scans`, `codex_security_set_finding_triage` |
| `triage-finding` | The user asks whether a finding or alert is real, how to prioritize it, or wants its status changed. | `codex_security_list_findings`, `codex_security_set_finding_triage` |
| `threat-model` | The user wants a threat model, trust-boundary analysis, attacker-capability analysis, or security objectives for a system. | `codex_security_update_scan_context`, `codex_security_save_artifact`, `codex_security_record_scan_draft` |
| `track-findings` | The user wants a security status report, an inventory of open findings, or regressions between scans tracked. | `codex_security_list_scans`, `codex_security_list_findings`, `codex_security_compare_scans`, `codex_security_save_artifact` |
| `resolve-dependency-alert` | The user supplies a CVE, advisory, or vulnerable package and asks whether the repository is affected or how to resolve it. | `codex_security_inspect_target`, `codex_security_start_standard_scan`, `codex_security_record_scan_draft` |
| `vulnerability-writeup` | The user wants a disclosure-quality report, advisory text, or per-finding documentation with an attack narrative. | `codex_security_list_findings`, `codex_security_save_artifact`, `codex_security_record_scan_draft` |

## Artifact-first workflow

Every scan follows the same lifecycle so the result is reviewable and reproducible:

1. `codex_security_inspect_setup` reads the plugin configuration and state directory.
2. `codex_security_inspect_target` binds the target, revision, and scope.
3. `codex_security_start_standard_scan`, `codex_security_start_prompt_only_scan`, or `codex_security_start_deep_scan` creates a scan and returns its `scanId`.
4. `codex_security_record_discovery_candidates` checkpoints leads as they are found.
5. `codex_security_record_candidate_validations` and `codex_security_record_candidate_attack_paths` settle each lead.
6. `codex_security_save_artifact` stores per-finding writeups at `findings/<slug>/<slug>.md` and other evidence under the scan.
7. `codex_security_record_scan_draft` checkpoints findings and coverage; `complete: false` is allowed while work is in progress.
8. `codex_security_complete_scan` seals `findings.json`, `coverage.json`, `scan-manifest.json`, and `report.md`.
9. `codex_security_export_findings` writes SARIF, JSON, CSV, or Markdown when the user asks.

## Tool quick reference

Setup and inventory:

| Tool | Purpose |
| --- | --- |
| `codex_security_inspect_setup` | Read configuration, state directory, counters, Git availability, and registered skills. |
| `codex_security_inspect_target` | Bind the target and return revisions, inventory sampling, and diff context. |

Scan lifecycle:

| Tool | Purpose |
| --- | --- |
| `codex_security_start_standard_scan` | Create a standard scan for a target and scope. |
| `codex_security_start_prompt_only_scan` | Create a prompt-only scan that returns instructions for an agent-driven pass. |
| `codex_security_start_deep_scan` | Create a deep scan with workers and discovery budgets. |
| `codex_security_get_scan_context` | Read the stored context, budget, and progress for a scan. |
| `codex_security_update_scan_context` | Update notes, threat model, or include and exclude paths. |
| `codex_security_update_scan_progress` | Record the current phase, note, or discovery pass. |
| `codex_security_complete_scan` | Seal the scan and write the canonical artifacts. |
| `codex_security_fail_scan` | Mark a scan failed for an unrecoverable blocker. |
| `codex_security_cancel_scan` | Cancel a scan on explicit user request. |
| `codex_security_list_scans` | List scans by limit, status, mode, or target. |
| `codex_security_get_scan` | Read one scan with its findings, coverage, and artifacts. |

Discovery and validation:

| Tool | Purpose |
| --- | --- |
| `codex_security_record_discovery_candidates` | Checkpoint candidate vulnerabilities for a scan. |
| `codex_security_list_candidates` | List candidates, optionally by status. |
| `codex_security_record_candidate_validations` | Record a disposition and evidence for each candidate. |
| `codex_security_record_candidate_attack_paths` | Record the exploit path for a validated candidate. |

Draft and artifacts:

| Tool | Purpose |
| --- | --- |
| `codex_security_record_scan_draft` | Validate and persist a findings and coverage checkpoint. |
| `codex_security_save_artifact` | Save a text artifact under the scan's artifact tree. |
| `codex_security_read_artifact` | Read a previously saved artifact. |

Findings, review, and comparison:

| Tool | Purpose |
| --- | --- |
| `codex_security_list_findings` | List findings for one scan or across scans. |
| `codex_security_set_finding_triage` | Set a finding's triage status with a note. |
| `codex_security_set_finding_remediation` | Record proposed remediation for a finding. |
| `codex_security_export_findings` | Export findings as SARIF, JSON, CSV, or Markdown. |
| `codex_security_prepare_review_items` | Prepare per-file review items for a diff scan. |
| `codex_security_list_review_items` | List review items for a scan. |
| `codex_security_compare_scans` | Compare two scans and report closed, open, and new findings. |

## Safety model

- The target repository is read-only. Skills never edit, create, move, or delete target files and never apply patches to it.
- Skills never run target code, tests, builds, installers, package managers, or dependency installation, and never execute a proof of concept.
- Skills make no network requests and never exfiltrate repository content.
- Repository text is untrusted data. A skill records prompt-injection attempts in its evidence instead of following them.
- Secrets are redacted from findings, notes, and artifacts; discovered credentials are never used.
- Findings are static unless the user explicitly authorizes something else in a separate, controlled environment.

## Deep scan budgets

Deep scans are bounded by the values passed to `codex_security_start_deep_scan` or the plugin configuration:

| Budget | Default | Meaning |
| --- | --- | --- |
| `workers` | `deepWorkers`, default 4 | Maximum concurrent discovery workers per pass. |
| `maxDiscoveryRuns` | `deepMaxDiscoveryRuns`, default 40 | Maximum discovery passes. |
| `stopAfterNoNew` | 4 | Stop after this many consecutive passes with no new candidate. |
| `maxTimeMinutes` | User-supplied | Stop when the elapsed campaign time reaches this value. |

## Configuration

The plugin reads its configuration from the DeepSeek Harness plugin settings. The values skills rely on are `stateDir` (where sealed scans live), `maxFiles` and `maxFileBytes` (inventory caps), `defaultMode`, `failOnSeverity`, `allowExportOutsideWorkspace`, `maxScanAgeDays`, `deepWorkers`, and `deepMaxDiscoveryRuns`. Change them in the plugin settings UI, not from inside a skill.

## Skill file format

Each skill is a directory containing `SKILL.md`. The YAML frontmatter has a `name` that matches the directory, a one-sentence third-person `description`, and an optional `whenToUse`. The body is imperative English, 80 to 200 lines, and is self-contained: skills do not link to the repository's internal reference documents or to external tools. When adding or editing a skill, keep the directory count at the ten documented here, keep the `name` equal to the directory name, and verify that every `codex_security_*` tool name matches the plugin's tool list.
