---
description: Run Scrim's health checks — deny rules, policy, vault, hooks, Presidio.
---

Call the Scrim MCP tool `scrim_doctor` and present its output:

- One line per check: `name` `status` (pass/warn/fail) and `detail`.
- If any check has status `fail`, highlight it loudly — that means Scrim is not effectively protecting the session.
- If `deny-rules-present` fails, suggest running `scripts/install-deny-rules.sh` from the plugin repo.
- If `vault-healthy` is `warn`, mention that LRU eviction will start dropping entries and explain that in-flight Writes referencing evicted tokens will be denied (fail-closed).

Don't try to fix anything yourself unless the user asks. The doctor diagnoses; the user (or scripts/install-deny-rules.sh) remediates.
