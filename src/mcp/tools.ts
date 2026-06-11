// MCP tool handlers for the Scrim server.
//
// Each ingress tool reads from disk or executes a command, then runs the result
// through processText() before returning. The hooks (Write/Edit detokenize and
// Bash guard) are NOT registered here — they live as separate executables under
// bin/ because Claude Code spawns hook commands as standalone processes.

import { readFileSync, statSync, readdirSync, existsSync, openSync, readSync, closeSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, resolve, isAbsolute } from "node:path";
import ignore, { type Ignore } from "ignore";
import { processText, BlockedError } from "./process.js";
import { append as auditAppend, hashValue, summary as auditSummary, tail as auditTail } from "../audit/index.js";
import { detectStreaming } from "../engine/streaming.js";
import { actionFor } from "../policy/index.js";
import type { Context } from "./context.js";

// Heuristic binary check: presence of a null byte in the first 8 KiB.
function looksBinary(buf: Buffer): boolean {
  const slice = buf.subarray(0, Math.min(buf.length, 8192));
  for (let i = 0; i < slice.length; i++) if (slice[i] === 0) return true;
  return false;
}

function resolveAgainst(root: string, p: string): string {
  return isAbsolute(p) ? p : resolve(root, p);
}

// ---------------- safe_read ----------------

export interface SafeReadArgs {
  path: string;
  maxBytes?: number;
  // Read only this byte slice [start, end) and run the whole-buffer pipeline
  // on the slice. Bounded by maxBytes against (end - start). Use this to
  // fetch a window of a file too large to read whole.
  byteRange?: [number, number];
}

export interface SafeReadDetectionSummary {
  ruleId: string;
  class: string;
  count: number;
  tokenRefs: string[];
  lines: number[];
}

// safe_read returns `kind: "content"` when the redacted file/slice fits in
// memory, and `kind: "summary"` for files larger than maxBytes (the chunked
// streaming path). Callers must check kind before reading content / summary.
export type SafeReadResult =
  | {
      kind: "content";
      path: string;
      bytes: number;
      detections: number;
      content: string;
      blocked?: { ruleId: string; class: string };
    }
  | {
      kind: "summary";
      path: string;
      bytes: number;
      fileSize: number;
      summary: SafeReadDetectionSummary[];
      blocked?: { ruleId: string; class: string };
    };

export function safeRead(args: SafeReadArgs, ctx: Context): SafeReadResult {
  const target = resolveAgainst(ctx.repoRoot, args.path);
  const maxBytes = args.maxBytes ?? ctx.policy.detection.maxBytes;
  const stat = statSync(target);
  const relPath = relative(ctx.repoRoot, target) || args.path;

  if (args.byteRange) {
    return safeReadSlice(target, relPath, args.byteRange, maxBytes, ctx);
  }

  if (stat.size > maxBytes) {
    return safeReadStreaming(target, relPath, stat.size, ctx);
  }

  const buf = readFileSync(target);
  if (looksBinary(buf)) {
    throw new Error(`scrim: ${args.path} appears to be binary; refusing to redact`);
  }
  const text = buf.toString("utf8");
  try {
    const { output, detections } = processText(text, "safe_read", ctx);
    return {
      kind: "content",
      path: relPath,
      bytes: buf.length,
      detections: detections.length,
      content: output,
    };
  } catch (err) {
    if (err instanceof BlockedError) {
      return {
        kind: "content",
        path: relPath,
        bytes: buf.length,
        detections: 0,
        content: "",
        blocked: { ruleId: err.ruleId, class: err.klass },
      };
    }
    throw err;
  }
}

function safeReadSlice(
  target: string,
  relPath: string,
  range: [number, number],
  maxBytes: number,
  ctx: Context,
): SafeReadResult {
  const [start, end] = range;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start) {
    throw new Error(`scrim: byteRange must be [start, end) with 0 <= start < end (got [${start}, ${end}])`);
  }
  const sliceLen = end - start;
  if (sliceLen > maxBytes) {
    throw new Error(`scrim: byteRange slice (${sliceLen} bytes) exceeds maxBytes (${maxBytes})`);
  }
  const fd = openSync(target, "r");
  let buf: Buffer;
  try {
    buf = Buffer.alloc(sliceLen);
    const got = readSync(fd, buf, 0, sliceLen, start);
    if (got < sliceLen) buf = buf.subarray(0, got);
  } finally {
    closeSync(fd);
  }
  if (looksBinary(buf)) {
    throw new Error(`scrim: ${relPath} byte range appears to be binary; refusing to redact`);
  }
  const text = buf.toString("utf8");
  try {
    const { output, detections } = processText(text, "safe_read", ctx);
    return {
      kind: "content",
      path: relPath,
      bytes: buf.length,
      detections: detections.length,
      content: output,
    };
  } catch (err) {
    if (err instanceof BlockedError) {
      return {
        kind: "content",
        path: relPath,
        bytes: buf.length,
        detections: 0,
        content: "",
        blocked: { ruleId: err.ruleId, class: err.klass },
      };
    }
    throw err;
  }
}

function safeReadStreaming(
  target: string,
  relPath: string,
  fileSize: number,
  ctx: Context,
): SafeReadResult {
  const { detections: raw } = detectStreaming(target, ctx.engine, {
    chunkBytes: ctx.policy.detection.chunkBytes,
    overlapBytes: ctx.policy.detection.chunkOverlap,
  });

  const buckets = new Map<string, SafeReadDetectionSummary>();
  let blocked: { ruleId: string; class: string } | undefined;

  for (const d of raw) {
    const action = actionFor(ctx.policy, d.span.class);
    const valueHash = hashValue(ctx.repoRoot, d.value);

    if (action === "allow") continue;

    if (action === "block") {
      auditAppend(ctx.repoRoot, {
        ruleId: d.span.ruleId, tool: "safe_read", action: "block", valueHash,
      });
      blocked = { ruleId: d.span.ruleId, class: d.span.class };
      break;
    }

    let bucket = buckets.get(d.span.ruleId);
    if (!bucket) {
      bucket = { ruleId: d.span.ruleId, class: d.span.class, count: 0, tokenRefs: [], lines: [] };
      buckets.set(d.span.ruleId, bucket);
    }
    bucket.count++;
    bucket.lines.push(d.line);

    if (action === "redact") {
      const tokenRef = ctx.vault.tokenize(d.value, d.span.ruleId, d.span.ruleId);
      bucket.tokenRefs.push(tokenRef);
      auditAppend(ctx.repoRoot, {
        ruleId: d.span.ruleId, tool: "safe_read", action: "redact", tokenRef, valueHash,
      });
      for (const evicted of ctx.vault.drainEvicted()) {
        auditAppend(ctx.repoRoot, {
          ruleId: "vault-evict", tool: "safe_read", action: "evict", tokenRef: evicted,
          context: { reason: "lru-cap" },
        });
      }
    } else if (action === "alert") {
      auditAppend(ctx.repoRoot, {
        ruleId: d.span.ruleId, tool: "safe_read", action: "alert", valueHash,
      });
    }
  }

  return {
    kind: "summary",
    path: relPath,
    bytes: fileSize,
    fileSize,
    summary: Array.from(buckets.values()),
    ...(blocked ? { blocked } : {}),
  };
}

// ---------------- safe_grep ----------------

export interface SafeGrepArgs {
  pattern: string;
  path?: string;
  flags?: string;       // regex flags, e.g. "i"
  maxMatches?: number;
}
export interface SafeGrepMatch {
  path: string;
  line: number;
  text: string;         // already redacted
}
export interface SafeGrepResult {
  matches: SafeGrepMatch[];
  truncated: boolean;
}

// Hardcoded directory patterns added on top of the repo's own .gitignore. `.git`
// and `.scrim` are never interesting; the rest are ecosystem dependency dirs
// that crowd out signal in monorepos whose .gitignore doesn't list them.
const FALLBACK_IGNORES = [
  ".git/",
  ".scrim/",
  "node_modules/",
  "dist/",
  "build/",
  "bin/",
  "target/",
  "__pycache__/",
  ".venv/",
  "vendor/",
  "Pods/",
  "obj/",
  "packages/",
  ".terraform/",
];

function loadIgnore(repoRoot: string): Ignore {
  const ig = ignore();
  ig.add(FALLBACK_IGNORES);
  const gi = join(repoRoot, ".gitignore");
  if (existsSync(gi)) {
    try {
      ig.add(readFileSync(gi, "utf8"));
    } catch {
      // best-effort; fall back to the hardcoded list above
    }
  }
  return ig;
}

function walkFiles(root: string, out: string[], ig: Ignore, repoRoot: string): void {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = join(root, e.name);
    // ignore-library wants posix-style relative paths from the gitignore root.
    let rel = relative(repoRoot, p).split("\\").join("/");
    if (!rel || rel.startsWith("..")) continue;
    if (e.isDirectory()) rel += "/";
    if (ig.ignores(rel)) continue;
    if (e.isDirectory()) walkFiles(p, out, ig, repoRoot);
    else if (e.isFile()) out.push(p);
  }
}

export function safeGrep(args: SafeGrepArgs, ctx: Context): SafeGrepResult {
  const re = new RegExp(args.pattern, (args.flags ?? "") + (args.flags?.includes("g") ? "" : "g"));
  const start = resolveAgainst(ctx.repoRoot, args.path ?? ".");
  const maxMatches = args.maxMatches ?? 200;

  const stat = statSync(start);
  const files: string[] = [];
  if (stat.isDirectory()) {
    const ig = loadIgnore(ctx.repoRoot);
    walkFiles(start, files, ig, ctx.repoRoot);
  } else {
    files.push(start);
  }

  const matches: SafeGrepMatch[] = [];
  let truncated = false;
  for (const file of files) {
    let buf: Buffer;
    try {
      buf = readFileSync(file);
    } catch {
      continue;
    }
    if (looksBinary(buf)) continue;
    const lines = buf.toString("utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (!re.test(line)) {
        re.lastIndex = 0;
        continue;
      }
      re.lastIndex = 0;
      try {
        const { output } = processText(line, "safe_grep", ctx);
        matches.push({ path: relative(ctx.repoRoot, file) || file, line: i + 1, text: output });
      } catch (err) {
        if (err instanceof BlockedError) {
          matches.push({
            path: relative(ctx.repoRoot, file) || file,
            line: i + 1,
            text: `[scrim: blocked by ${err.ruleId}]`,
          });
        } else {
          throw err;
        }
      }
      if (matches.length >= maxMatches) {
        truncated = true;
        return { matches, truncated };
      }
    }
  }
  return { matches, truncated };
}

// ---------------- safe_shell ----------------

export interface SafeShellArgs {
  command: string;
  timeoutMs?: number;
  cwd?: string;
}
export interface SafeShellResult {
  stdout: string;       // redacted
  stderr: string;       // redacted
  exitCode: number | null;
  signal: string | null;
  detections: number;
  blocked?: { ruleId: string; class: string };
}

export function safeShell(args: SafeShellArgs, ctx: Context): SafeShellResult {
  const cwd = args.cwd ? resolveAgainst(ctx.repoRoot, args.cwd) : ctx.repoRoot;
  const res = spawnSync(args.command, {
    shell: true,
    cwd,
    timeout: args.timeoutMs ?? 30_000,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  const rawStdout = res.stdout ?? "";
  const rawStderr = res.stderr ?? "";
  try {
    const out = processText(rawStdout, "safe_shell", ctx);
    const err = processText(rawStderr, "safe_shell", ctx);
    return {
      stdout: out.output,
      stderr: err.output,
      exitCode: res.status,
      signal: res.signal ? String(res.signal) : null,
      detections: out.detections.length + err.detections.length,
    };
  } catch (e) {
    if (e instanceof BlockedError) {
      return {
        stdout: "", stderr: "",
        exitCode: res.status, signal: res.signal ? String(res.signal) : null,
        detections: 0,
        blocked: { ruleId: e.ruleId, class: e.klass },
      };
    }
    throw e;
  }
}

// ---------------- safe_write_token ----------------

export interface SafeWriteTokenArgs {
  token: string;
  newValue: string;
}
export interface SafeWriteTokenResult {
  token: string;
  previousValueHash: string;     // first 12 chars of salted sha256 — for audit correlation
}

export function safeWriteToken(args: SafeWriteTokenArgs, ctx: Context): SafeWriteTokenResult {
  const { previousValueHash: priorFullHash } = ctx.vault.updateValue(args.token, args.newValue);
  // Compress the full hex hash from the vault (raw sha256) down to the salted
  // 12-char audit hash for consistency with the rest of the log.
  const auditedPriorHash = priorFullHash.slice(0, 12);
  auditAppend(ctx.repoRoot, {
    ruleId: "safe-write-token",
    tool: "safe_write_token",
    action: "rewrite",
    tokenRef: args.token,
    valueHash: hashValue(ctx.repoRoot, args.newValue),
    context: { previousValueHash: auditedPriorHash },
  });
  return { token: args.token, previousValueHash: auditedPriorHash };
}

// ---------------- scrim_status ----------------

export interface ScrimStatusResult {
  policy: {
    version: number;
    failClosed: boolean;
    detection: { gitleaks: boolean; presidio: boolean; fastPiiRegex: boolean };
    actions: Record<string, string>;
    repoTuning: { envKeys: number; internalDomains: number; customPatterns: number };
  };
  vault: { size: number; createdAt: string };
  audit: { total: number; byAction: Record<string, number>; recent: unknown[] };
  hooks: {
    detokenize: { expectedPath: string; present: boolean };
    bashGuard: { expectedPath: string; present: boolean };
  };
}

export function scrimStatus(ctx: Context): ScrimStatusResult {
  const sum = auditSummary(ctx.repoRoot);
  const recent = auditTail(ctx.repoRoot, 5);
  const pluginRoot = process.env["SCRIM_PLUGIN_ROOT"] ?? "";
  const detokenizePath = pluginRoot ? join(pluginRoot, "bin", "scrim-detokenize.js") : "";
  const bashGuardPath = pluginRoot ? join(pluginRoot, "bin", "scrim-bash-guard.js") : "";

  return {
    policy: {
      version: ctx.policy.version,
      failClosed: ctx.policy.failClosed,
      detection: ctx.policy.detection,
      actions: ctx.policy.actions,
      repoTuning: {
        envKeys: ctx.engine.tuned.envKeys.size,
        internalDomains: ctx.engine.tuned.internalDomainPatterns.length,
        customPatterns: ctx.engine.tuned.customPatterns.length,
      },
    },
    vault: ctx.vault.stats(),
    audit: { total: sum.total, byAction: sum.byAction, recent },
    hooks: {
      detokenize: { expectedPath: detokenizePath, present: detokenizePath ? existsSync(detokenizePath) : false },
      bashGuard:  { expectedPath: bashGuardPath,  present: bashGuardPath  ? existsSync(bashGuardPath)  : false },
    },
  };
}

// ---------------- scrim_doctor ----------------

// The deny-list a project's .claude/settings.json should carry so the agent is
// actually routed through Scrim's safe_* tools. Each entry is matched verbatim
// against the user's permissions.deny[] array. Keep in sync with
// scripts/install-deny-rules.sh.
export const REQUIRED_DENY_RULES: string[] = [
  "Read(./.env*)",
  "Read(**/*.pem)",
  "Read(**/secrets/**)",
  "Bash(env)",
  "Bash(printenv*)",
  "Bash(*kubectl get secret*)",
];

export type DoctorStatus = "pass" | "warn" | "fail";

export interface DoctorCheck {
  name: string;
  status: DoctorStatus;
  detail: string;
}

export interface DoctorReport {
  ok: boolean;
  checks: DoctorCheck[];
}

interface ClaudeSettings {
  permissions?: { deny?: unknown };
}

function readDenyList(repoRoot: string): { source: string; deny: string[] | null } {
  const p = join(repoRoot, ".claude", "settings.json");
  if (!existsSync(p)) return { source: p, deny: null };
  try {
    const raw = readFileSync(p, "utf8");
    const parsed = JSON.parse(raw) as ClaudeSettings;
    const deny = parsed.permissions?.deny;
    if (!Array.isArray(deny)) return { source: p, deny: [] };
    return { source: p, deny: deny.filter((x): x is string => typeof x === "string") };
  } catch {
    return { source: p, deny: null };
  }
}

function checkDenyRules(repoRoot: string): DoctorCheck {
  const { source, deny } = readDenyList(repoRoot);
  if (deny === null) {
    return {
      name: "deny-rules-present",
      status: "fail",
      detail: `${source} missing or unparseable. Run scripts/install-deny-rules.sh to add Scrim's recommended deny list — without it, the agent may use native Read/Bash on sensitive paths and bypass Scrim.`,
    };
  }
  const missing = REQUIRED_DENY_RULES.filter((r) => !deny.includes(r));
  if (missing.length === 0) {
    return {
      name: "deny-rules-present",
      status: "pass",
      detail: `${REQUIRED_DENY_RULES.length}/${REQUIRED_DENY_RULES.length} recommended deny rules present in ${source}`,
    };
  }
  return {
    name: "deny-rules-present",
    status: "fail",
    detail: `${missing.length} of ${REQUIRED_DENY_RULES.length} recommended deny rules missing from ${source}: ${missing.join(", ")}. Run scripts/install-deny-rules.sh to add them.`,
  };
}

function checkPolicy(ctx: Context): DoctorCheck {
  // Context was built with a parsed policy already; if we got here, it loaded.
  return {
    name: "policy-loadable",
    status: "pass",
    detail: `policy v${ctx.policy.version} loaded; failClosed=${ctx.policy.failClosed}`,
  };
}

function checkVault(ctx: Context): DoctorCheck {
  const cap = ctx.policy.vault.maxEntries;
  const size = ctx.vault.size();
  if (cap > 0 && size >= cap * 0.9) {
    return {
      name: "vault-healthy",
      status: "warn",
      detail: `vault at ${size}/${cap} entries (>=90% of cap). LRU eviction will start dropping entries; in-flight Writes referencing evicted tokens will be denied.`,
    };
  }
  return {
    name: "vault-healthy",
    status: "pass",
    detail: cap > 0 ? `${size}/${cap} entries` : `${size} entries (cap disabled)`,
  };
}

function checkHooks(): DoctorCheck {
  const pluginRoot = process.env["SCRIM_PLUGIN_ROOT"] ?? "";
  if (!pluginRoot) {
    return {
      name: "hooks-registered",
      status: "warn",
      detail: "SCRIM_PLUGIN_ROOT env var not set; cannot verify hook binaries (status check from a non-MCP context).",
    };
  }
  const bins = ["scrim-detokenize.js", "scrim-bash-guard.js", "scrim-stop.js"];
  const missing = bins.filter((b) => !existsSync(join(pluginRoot, "bin", b)));
  if (missing.length > 0) {
    return {
      name: "hooks-registered",
      status: "fail",
      detail: `missing hook binaries in ${pluginRoot}/bin: ${missing.join(", ")}. Run npm run build.`,
    };
  }
  return { name: "hooks-registered", status: "pass", detail: `${bins.length} hook binaries present in ${pluginRoot}/bin` };
}

function checkPresidio(ctx: Context): DoctorCheck | null {
  if (!ctx.policy.detection.presidio) return null;
  const cmd = ctx.policy.detection.presidioCommand ?? "scrim-presidio";
  const which = spawnSync("which", [cmd], { encoding: "utf8" });
  if (which.status !== 0) {
    return {
      name: "presidio-binary",
      status: "warn",
      detail: `policy enables Presidio but '${cmd}' is not on PATH. Presidio detection will silently return no spans.`,
    };
  }
  return { name: "presidio-binary", status: "pass", detail: `${cmd} resolved on PATH` };
}

export function scrimDoctor(ctx: Context): DoctorReport {
  const checks: DoctorCheck[] = [
    checkDenyRules(ctx.repoRoot),
    checkPolicy(ctx),
    checkVault(ctx),
    checkHooks(),
  ];
  const presidio = checkPresidio(ctx);
  if (presidio) checks.push(presidio);

  const ok = checks.every((c) => c.status !== "fail");
  return { ok, checks };
}
