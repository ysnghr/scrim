// Append-only audit log at .scrim/audit/detections.jsonl.
//
// One JSON object per line. POSIX appends shorter than PIPE_BUF (typically
// 4 KiB on macOS/Linux) are atomic, so multiple processes can append without
// interleaving lines as long as each entry stays small. Entries here are
// well under that limit.
//
// Value-free by design. The type system disallows a `value` field, and write()
// strips any extra keys defensively — the audit log must never let a leaked
// secret bleed in via a misuse of the API.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { createHash, randomBytes } from "node:crypto";

export type AuditAction = "redact" | "block" | "alert" | "allow" | "restore" | "rewrite" | "evict" | "wipe";

export interface AuditEntry {
  ts?: string;             // ISO-8601; auto-filled if omitted
  ruleId: string;          // e.g. "aws-access-key-id" or "tuned-env-key"
  tool: string;            // "safe_read" | "safe_grep" | "safe_shell" | "Bash" | "Write" | ...
  action: AuditAction;
  tokenRef?: string;       // ⟦scrim:class:id⟧ — references the vault entry, never the value
  valueHash?: string;      // salted sha256 prefix; for dedupe across the log, not reversible
  context?: Record<string, string | number | boolean>; // tool path, command summary, etc.
}

// Whitelist of keys allowed in a serialized entry. Anything else is stripped.
const ALLOWED_KEYS = new Set([
  "ts",
  "ruleId",
  "tool",
  "action",
  "tokenRef",
  "valueHash",
  "context",
]);

const SALT_BYTES = 16;

function paths(repoRoot: string) {
  const dir = join(repoRoot, ".scrim", "audit");
  return {
    dir,
    logPath: join(dir, "detections.jsonl"),
    saltPath: join(dir, "salt"),
  };
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function loadOrCreateSalt(repoRoot: string): Buffer {
  const { dir, saltPath } = paths(repoRoot);
  if (existsSync(saltPath)) {
    const salt = readFileSync(saltPath);
    if (salt.length === SALT_BYTES) return salt;
    // Wrong length — overwrite. The audit salt is not security-critical (it
    // protects against cross-run value linkage, not authn/authz), so silently
    // healing is acceptable.
  }
  ensureDir(dir);
  const salt = randomBytes(SALT_BYTES);
  writeFileSync(saltPath, salt, { mode: 0o600 });
  return salt;
}

function sanitize(entry: AuditEntry): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(entry)) {
    if (!ALLOWED_KEYS.has(k)) continue;
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

export function append(repoRoot: string, entry: AuditEntry): void {
  const { dir, logPath } = paths(repoRoot);
  ensureDir(dir);
  const sanitized = sanitize(entry);
  if (sanitized["ts"] === undefined) sanitized["ts"] = new Date().toISOString();
  const line = JSON.stringify(sanitized) + "\n";
  if (line.length > 4000) {
    // Stay well under PIPE_BUF so cross-process appends don't interleave.
    throw new Error(`scrim: audit entry too large (${line.length} bytes)`);
  }
  appendFileSync(logPath, line);
}

export function tail(repoRoot: string, n: number): AuditEntry[] {
  const { logPath } = paths(repoRoot);
  if (!existsSync(logPath)) return [];
  const text = readFileSync(logPath, "utf8");
  if (text.length === 0) return [];
  const lines = text.split("\n");
  const out: AuditEntry[] = [];
  // Walk backwards so we collect the latest N first, then reverse for chronology.
  for (let i = lines.length - 1; i >= 0 && out.length < n; i--) {
    const line = lines[i];
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as AuditEntry);
    } catch {
      // Skip malformed lines rather than blowing up — the log is best-effort
      // for humans, not a source of truth.
    }
  }
  return out.reverse();
}

export function hashValue(repoRoot: string, value: string): string {
  const salt = loadOrCreateSalt(repoRoot);
  return createHash("sha256")
    .update(salt)
    .update(value, "utf8")
    .digest("hex")
    .slice(0, 12);
}

// Convenience for /scrim:audit and /scrim:status; counts entries by action.
export function summary(repoRoot: string): { total: number; byAction: Record<AuditAction, number> } {
  const { logPath } = paths(repoRoot);
  const byAction: Record<AuditAction, number> = {
    redact: 0, block: 0, alert: 0, allow: 0, restore: 0, rewrite: 0, evict: 0, wipe: 0,
  };
  if (!existsSync(logPath)) return { total: 0, byAction };
  let total = 0;
  for (const line of readFileSync(logPath, "utf8").split("\n")) {
    if (!line) continue;
    try {
      const e = JSON.parse(line) as AuditEntry;
      total++;
      if (e.action in byAction) byAction[e.action as AuditAction]++;
    } catch {
      // ignore
    }
  }
  return { total, byAction };
}

// Test/diagnostic helper. The audit log path used by all of the above.
export function logPathFor(repoRoot: string): string {
  return paths(repoRoot).logPath;
}

// `dirname` is imported to keep the public surface free of path joining;
// callers should not need to know the layout.
export const _internal = { paths, dirname };
