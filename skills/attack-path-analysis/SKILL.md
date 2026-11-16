---
name: attack-path-analysis
description: Analyze the reachability and practical impact of a candidate security finding, or perform the attack-path phase of an active scan.
---

# Analyze attack paths

Start with the candidate and its evidence. Trace attacker-controlled input or state through entry points and trust boundaries to the sensitive operation, including relevant callers, configuration, permissions, and enforcement points. Identify necessary preconditions, attacker capabilities, effects, compensating controls, and specific counterevidence. Cite source locations and separate observed facts from assumptions; an unproven path remains uncertain.

Estimate impact and likelihood independently of the candidate's initial severity. Explain which missing evidence could change the conclusion. Do not run target code or perform network activity without authorization. If the candidate belongs to a running scan, record the analysis using `codex_security_record_candidate_attack_paths` with its candidate ID, summary, steps, preconditions, controls, impact, and likelihood. This records the assessment; it does not independently verify reachability.
