---
description: Show Scrim status — active detection rules, vault size, recent detections, hook health.
---

Call the Scrim MCP tool `scrim_status` and present its output to the user in a compact summary:

- Active detection sources (gitleaks / fast_pii_regex / presidio) and rule counts
- Number of tokens currently in the session vault
- Last N detections from the audit log (rule id, tool, action, timestamp — never the value)
- Hook registration status (detokenize on Write|Edit|MultiEdit, bash-guard on Bash)

If any subsystem is unhealthy (engine errored, vault unavailable, hooks not registered), highlight it and remind the user that Scrim is fail-closed in that state.
