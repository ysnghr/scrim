// MCP tool handlers for the Scrim server.
//
// Each ingress tool reads from disk or executes a command, then runs the result
// through processText() before returning. The hooks (Write/Edit detokenize and
// Bash guard) are NOT registered here — they live as separate executables under
// bin/ because Claude Code spawns hook commands as standalone processes.

import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, resolve, isAbsolute } from "node:path";
import { processText, BlockedError } from "./process.js";
import { summary as auditSummary, tail as auditTail } from "../audit/index.js";
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
}
export interface SafeReadResult {
  path: string;
  bytes: number;
  detections: number;
  content: string;
  blocked?: { ruleId: string; class: string };
}

export function safeRead(args: SafeReadArgs, ctx: Context): SafeReadResult {
  const target = resolveAgainst(ctx.repoRoot, args.path);
  const maxBytes = args.maxBytes ?? 2_000_000;
  const stat = statSync(target);
  if (stat.size > maxBytes) {
    throw new Error(`scrim: ${args.path} exceeds maxBytes (${stat.size} > ${maxBytes})`);
  }
  const buf = readFileSync(target);
  if (looksBinary(buf)) {
    throw new Error(`scrim: ${args.path} appears to be binary; refusing to redact`);
  }
  const text = buf.toString("utf8");
  try {
    const { output, detections } = processText(text, "safe_read", ctx);
    return {
      path: relative(ctx.repoRoot, target) || args.path,
      bytes: buf.length,
      detections: detections.length,
      content: output,
    };
  } catch (err) {
    if (err instanceof BlockedError) {
      return {
        path: relative(ctx.repoRoot, target) || args.path,
        bytes: buf.length,
        detections: 0,
        content: "",
        blocked: { ruleId: err.ruleId, class: err.klass },
      };
    }
    throw err;
  }
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

// Skip these directories during recursive search — they're never interesting
// and tend to be huge.
const GREP_SKIP = new Set([".git", "node_modules", ".scrim", "dist", "build", "bin"]);

function walkFiles(root: string, out: string[]): void {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && GREP_SKIP.has(e.name)) continue;
    if (GREP_SKIP.has(e.name)) continue;
    const p = join(root, e.name);
    if (e.isDirectory()) walkFiles(p, out);
    else if (e.isFile()) out.push(p);
  }
}

export function safeGrep(args: SafeGrepArgs, ctx: Context): SafeGrepResult {
  const re = new RegExp(args.pattern, (args.flags ?? "") + (args.flags?.includes("g") ? "" : "g"));
  const start = resolveAgainst(ctx.repoRoot, args.path ?? ".");
  const maxMatches = args.maxMatches ?? 200;

  const stat = statSync(start);
  const files: string[] = [];
  if (stat.isDirectory()) walkFiles(start, files);
  else files.push(start);

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
