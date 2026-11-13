# dsh-codex-security — implementation specification

Status: authoritative for this repository. The host plugin is an independent
DeepSeek Harness re-implementation of OpenAI codex-security's scan model:
sealed scan artifacts, skill-driven review workflow, deep-scan orchestration,
and SARIF/JSON export.

## Product surface

- npm package: `dsh-codex-security` (bare name, public).
- DSH plugin name (export const name): `codex-security`.
- Loader patch row id: `codex-security`.
- Host tools are prefixed `codex_security_` (27 tools, table below).
- Client UI: one settings section "Codex Security" ("代码安全" in zh locale) that
  renders the scan workbench (scan list, scan detail, findings, coverage,
  export buttons) against the HTTP routes below.
- Skills (registered at runtime with ctx.skills.register from `skills/<name>/SKILL.md`):
  `security-scan`, `security-diff-scan`, `deep-security-scan`, `fix-finding`,
  `verify-fix`, `triage-finding`, `threat-model`, `track-findings`,
  `resolve-dependency-alert`, `vulnerability-writeup`.

## Configuration (Schemastery)

| key | type | default | meaning |
| --- | --- | --- | --- |
| stateDir | string | "" | absolute override; empty = `<profile>/data/codex-security` |
| maxFiles | natural | 5000 | inventory cap per scan |
| maxFileBytes | natural | 1048576 | max bytes read from one file |
| defaultMode | union(standard,prompt-only,deep) | standard | mode for start tools when omitted |
| failOnSeverity | union(informational,low,medium,high,critical,off) | high | policy gate reported in complete/export |
| allowExportOutsideWorkspace | boolean | false | permit export paths outside cwd/stateDir |
| maxScanAgeDays | natural | 30 | UI retention hint only |
| deepWorkers | natural | 4 | default deep-scan worker count |
| deepMaxDiscoveryRuns | natural | 40 | default deep-scan discovery budget |

State dir: `<profile data>/codex-security` where profile patch is
`$DSH_HOME || ~/.dsh` + `profiles/<profile>/cordis.patch.yml`.

## Disk layout

```
<stateDir>/
  index.json                        # cached scan summaries (rebuildable)
  repositories/<repoKey>/scans/<scanId>/
    scan.json                       # internal record
    findings.json                   # sealed findings contract
    coverage.json                   # sealed coverage contract
    scan-manifest.json              # sealed manifest (hashes of artifacts)
    report.md                       # human report
    threat-model.md                 # optional
    sarif.json                      # optional artifact
    candidates.json                 # discovery candidates
    validations.json                # candidate validations
    attack-paths.json               # candidate attack paths
    triage.json                     # finding triage/remediation state
    review-items.json               # diff review items
    checkpoints/scan-draft.json     # latest semantic draft
    artifacts/<path>                # agent-saved artifacts (report fragments, PoCs)
```

repoKey = first 16 hex of sha256(abs target root). scanId = `cs_` + 24 hex.
Writes are atomic (tmp file + rename) and serialized with a lock file.

## Artifact contract

Identical semantics to codex-security schemas shipped under `schemas/`:

- findings.json: `documentType: "codex-security.findings"`, schemaVersion "1.0",
  scanId, findings[] with findingId `^csf_[a-f0-9]{24}$`, occurrenceId
  `^occ_[a-f0-9]{24}$`, ruleId, identity {anchor, instance?}, fingerprints
  {algorithm: "codex-security/v1", primary: "codex-security/v1:sha256:<64hex>"},
  title, summary, severity {level, score, rationale?}, confidence {level, rationale},
  taxonomy {category, cwe?}, locations[{path,startLine,...}], remediation.
- coverage.json: `documentType: "codex-security.coverage"`, mode, inventoryStrategy,
  surfaces[{id,label,disposition,receiptRefs}], explicitExclusions, deferred.
- scan-manifest.json: `documentType: "codex-security.scan-manifest"`, scan {id,
  producer, status, startedAt/completedAt/sealedAt, target {kind,targetId,
  displayName,remote,revision,baseRevision,headRevision,snapshotDigest}, scope,
  findingsRef: "findings.json", artifacts[] (sha256 each), mode, warnings,
  review.excludedPaths}.
- Draft checkpoint (internal, mirrors tools/scan-draft.schema.json):
  {scanId, complete?, scope?, threatModel?, findings[], reviewState
  {surfaces[], explicitExclusions[], deferred[], resolvedDeferred?, openQuestions?}}.

Fingerprint rules: anchor input = ruleId + NUL + repo-relative path + NUL +
normalized evidence line (trimmed, whitespace-collapsed) or provided anchor;
primary = sha256 of that. findingId = `csf_` + sha256("finding" + NUL + primary)[0:24];
occurrenceId = `occ_` + sha256("occ" + NUL + primary + NUL + path + NUL + startLine)[0:24].
Ids stay stable across scans because line numbers are not in the anchor.

## Host tools (register with ctx.tools.register, JSON-Schema parameters)

All tools return a JSON object and render as pretty JSON text. Validation errors
throw Error with a `codex-security:` prefix; unknown scan -> `codex-security: scan not found`.

1. codex_security_inspect_setup {} — config, state dir, counters, git availability, skills.
2. codex_security_inspect_target {targetPath?, scope?, diffTarget?, workingTree?} — target facts, revisions, inventory sampling.
3. codex_security_start_standard_scan {targetPath?, includePaths?, excludePaths?, notes?, threatModel?} — create scan, return scanId + context + instructions.
4. codex_security_start_prompt_only_scan {targetPath?, includePaths?, excludePaths?, notes?} — same but promptOnly:true (no deep/orchestration semantics).
5. codex_security_start_deep_scan {targetPath?, includePaths?, excludePaths?, notes?, workers?, maxDiscoveryRuns?, stopAfterNoNew?, maxTimeMinutes?} — deep record.
6. codex_security_get_scan_context {scanId} — record, progress, draft presence, candidates, review items, artifact list.
7. codex_security_update_scan_context {scanId, notes?, threatModel?, includePaths?, excludePaths?}.
8. codex_security_update_scan_progress {scanId, phase?, note?, discoveryRun?} — heartbeat + phase.
9. codex_security_record_scan_draft {scanId, findings, reviewState{surfaces,explicitExclusions,deferred}, scope?, threatModel?, complete?} — validate + normalize + persist checkpoint; returns normalized finding ids.
10. codex_security_record_discovery_candidates {scanId, candidates[{ruleId,title,severity,path,startLine?,anchor?,instance?,summary?}]}.
11. codex_security_list_candidates {scanId, status?}.
12. codex_security_record_candidate_validations {scanId, validations[{candidateId,status,summary,method?,evidence?,limitations?}]}.
13. codex_security_record_candidate_attack_paths {scanId, attackPaths[{candidateId,summary,steps?,impact?,likelihood?,preconditions?,controls?}]}.
14. codex_security_save_artifact {scanId, path, content, mediaType?} — path must be relative under artifacts/.
15. codex_security_read_artifact {scanId, path} — returns text content (bounded).
16. codex_security_complete_scan {scanId, notes?} — seal artifacts + report + manifest, status completed.
17. codex_security_fail_scan {scanId, error}.
18. codex_security_cancel_scan {scanId, reason?}.
19. codex_security_list_scans {limit?, status?, mode?, target?} — summaries.
20. codex_security_get_scan {scanId} — record + findings + coverage + artifacts.
21. codex_security_list_findings {scanId?, severity?, status?, limit?} — global across scans when scanId absent.
22. codex_security_set_finding_triage {scanId, findingId, status, note?} — status enum open|triaged|fixed|false_positive|accepted_risk|wont_fix.
23. codex_security_set_finding_remediation {scanId, findingId, remediation, status?}.
24. codex_security_export_findings {scanId?, format: sarif|json|csv|markdown, outputPath?} — writes file under stateDir exports/ by default; returns path + count.
25. codex_security_prepare_review_items {scanId, files?} — diff mode review items per changed file.
26. codex_security_list_review_items {scanId, status?}.
27. codex_security_compare_scans {baseScanId, headScanId} — closed/open/new by fingerprint.

Skill names and tool names intentionally differ from codex-security (no `get_codex_security_*`
prefix); skills must use the tool names above.

## HTTP routes (webServer prefix route, base `/plugins/codex-security`)

- GET `/status` -> {ok, name, version, stateDir, scans, findings, config}
- GET `/scans?limit&offset&status&mode&target` -> {ok, scans:[{scanId,mode,status,target{displayName,kind,revision},createdAt,updatedAt,findingsCount,severityCounts,progress}],total}
- GET `/scans/:id` -> {ok, scan, findings:[finding], coverage, artifacts:[{path,size}]}
- GET `/findings?scanId&severity&status&limit&offset` -> {ok, findings, total}
- POST `/scans/:id/triage` body {findingId,status,note?} -> {ok, triage}
- POST `/scans/:id/remediation` body {findingId,remediation,status?} -> {ok, triage}
- GET `/export/:id?format=sarif|json|csv|markdown` -> file download (content-disposition).
- GET `/config` -> {ok, config}

All responses JSON except export; no-store; 404 for unknown scan; 400 for bad input.

## Client workbench requirements

Single module file `src/client/index.tsx` exporting name/inject=['slots']/apply.
Register `settings.section` id `codex-security`, order 41, label localized
(zip "Codex Security"). Must render: status header, scan list with mode/status/severity
counts, scan detail with findings table (severity chips, path:line, status select),
coverage summary, export links, refresh. Style via CSS tokens `--dsw-alias-*`,
scoped class prefix `.dcs-`; fetch `/plugins/codex-security/...`; no imports of
DSH client packages; guard fetch failures with an inline error state.
