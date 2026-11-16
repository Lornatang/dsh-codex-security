---
name: validation
description: Validate candidate security findings against source and counterevidence, or perform the validation phase of an active scan; use verify-fix for a claimed remediation.
---

# Validate candidates

Reconstruct each claim independently: attacker control, entry point, reachable path, missing or ineffective control, sensitive operation, prerequisites, and impact. Inspect callers and configuration as well as the cited lines, and actively look for constraints or protections that defeat the claim. Explain the evidence supporting and opposing each conclusion and separate confidence from impact.

Choose `reportable` when the evidence supports a meaningful risk, `suppressed` or `not_applicable` when evidence defeats or excludes the claim, and `deferred` when a material question remains unresolved. Never turn missing evidence into a confirmed result. For an active scan, call `codex_security_record_candidate_validations` with candidate ID, status, summary, method, evidence, and limitations. Include deferred work in the coverage. Dynamic reproduction, builds, network calls, and changes to the target require appropriate authorization and a suitable environment.
