---
description: Show recent detections from Scrim's append-only audit log.
argument-hint: "[N]"
---

Read the tail of `.scrim/audit/detections.jsonl` (default last 20 entries, or `$ARGUMENTS` if provided) and present a table:

| time | rule | tool | action | token ref |

Never reconstruct or guess the original value — the audit log is value-free by design.
