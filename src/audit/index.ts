// Append-only audit log at .scrim/audit/detections.jsonl.
// Records: timestamp, rule id, tool name, action (redact|block|alert), token reference/hash.
// Never the raw value. Value-free by design.

export interface AuditEntry {
  ts: string;          // ISO-8601
  ruleId: string;
  tool: string;        // safe_read | safe_grep | safe_shell | Bash | Write | ...
  action: "redact" | "block" | "alert" | "allow";
  tokenRef?: string;   // ⟦scrim:class:id⟧ — references vault entry, not the value
  valueHash?: string;  // sha256, salted per-session — for dedupe, not reversible
}

export function append(_root: string, _entry: AuditEntry): void {
  throw new Error("audit.append: not implemented yet");
}

export function tail(_root: string, _n: number): AuditEntry[] {
  throw new Error("audit.tail: not implemented yet");
}
