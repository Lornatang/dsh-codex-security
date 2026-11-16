# Codex Security compatibility

This comparison uses the locally installed Codex Security plugin 0.1.32 as the reference. DSH is an independent implementation and its public tools use the `codex_security_*` naming convention. Matching a skill name or document schema does not imply identical execution or coverage.

| Area | DSH behavior | Remaining difference |
| --- | --- | --- |
| Skills | All 15 reference skill names are registered, plus `resolve-dependency-alert`. Fix and verification workflows can perform work authorized by the user. | Workflow instructions are independently written and adapted to available DSH tools; they are not identical transcripts of the reference workflows. External tracking requires a separate authorized integration. |
| Findings and seal | New scans use the Codex v1 target, finding and occurrence identity algorithm, `coverage.completeness`, `scan.coverageRef`, evidence references, and the canonical threat-model projection. Legacy sealed scans are not rewritten. | A representative completed scan is checked with the reference validator when `CODEX_SECURITY_REFERENCE_ROOT` is supplied; this is not a guarantee for every possible input or historical artifact. |
| Drafts and candidates | Drafts accept `coverage` or DSH `reviewState`. Discovery, validation and attack-path records accept the Codex-style nested data as well as DSH's flat forms and retain the nested evidence. | Tool names and several arguments differ. DSH candidate submission appends and deduplicates rather than replacing the complete candidate set; Codex pagination and handoff claims are not implemented. |
| Deep scan | A durable coordinator launches isolated independent DSH workers, seals Standard child scans, merges findings conservatively and enforces worker, attempt, no-new and time limits. | DSH uses its own model provider and source-only worker tools; it does not reproduce the Codex SDK implementation or enforce token/dollar budgets. Automatic diff scans are unsupported. |
| Lifecycle and state | SQLite locks serialize campaign ownership, scans and indexes across processes. A hashed recovery claim permits authorized takeover. | Resume is explicit and requires a live DSH agent; SQLite locking requires trusted local storage. The claim is not a Codex handoff token. |
| Host integrations | DSH offers its own web workbench, formats and tools. | Codex desktop preflight, SDK worker orchestration, account-specific Daybreak access, and issue-provider integrations depend on the host and are not supplied by this package. |

DSH seals the evidence submitted by an agent and checks its structural consistency. It cannot independently guarantee the agent reviewed every claimed surface or followed skill instructions. `complete` describes the submitted coverage, not a proof that no vulnerabilities exist.


DSH `startActivation` uses a dedicated persistent worker preset and native tool guard. A successful full-file receipt verifies delivery through the DSH tool pipeline, not that a model understood every file or found every issue.
