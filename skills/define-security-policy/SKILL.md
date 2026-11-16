---
name: define-security-policy
description: Create, review, or update repository security-review policy when the user asks to define review scope, trust boundaries, or reporting criteria.
---

# Define security policy

Inspect the existing `SECURITY.md` and repository guidance, architecture, deployment assumptions, and any user-provided constraints before proposing policy. Describe the systems and trust boundaries in scope, attacker assumptions, meaningful security properties, exclusions with reasons, and how uncertainty should be handled. Separate observed design from proposed policy and avoid inventing commitments or disclosure contacts.

Preserve existing disclosure and support guidance. When the user requests a review, report concrete gaps and suggested wording; change a policy file only when the request authorizes creation or modification. Keep the policy scoped to the repository or component actually requested, and verify links and references against available evidence.
