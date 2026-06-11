// PreToolUse hook for Write|Edit|MultiEdit.
//
// Compiled to bin/scrim-detokenize.js and invoked by Claude Code per hooks.json.
// Reads the hook payload from stdin, restores ⟦scrim:...⟧ tokens via the
// session vault, and writes a hook output object back. Audits a "restore"
// entry per invocation so the audit log shows the egress side of the loop.
//
// Failure modes:
//   - vault unreadable          → emit deny (fail-closed) and exit 0
//   - any token unresolvable    → emit deny (fail-closed)
//   - any other unexpected err  → emit deny + stderr line + exit 1
// Exit code 0 with stdout JSON is the contract Claude Code uses to evaluate
// the hook; exit 1 is the unrecoverable internal-error escape hatch.

import { readFileSync } from "node:fs";
import { openVault } from "./vault/index.js";
import { append as auditAppend } from "./audit/index.js";
import { detokenize, type HookInput, type HookOutput } from "./hooks/detokenize.js";

function readStdin(): string {
  // Claude Code writes the entire payload then closes the pipe; a single
  // synchronous read from fd 0 is the simplest, robust approach.
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function emit(output: HookOutput): void {
  process.stdout.write(JSON.stringify(output));
}

function denyOutput(reason: string): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

function main(): void {
  const raw = readStdin();
  let input: HookInput;
  try {
    input = raw ? (JSON.parse(raw) as HookInput) : {};
  } catch {
    emit(denyOutput("scrim: malformed hook input"));
    return;
  }

  const repoRoot = input.cwd ?? process.cwd();

  let vault;
  try {
    vault = openVault(repoRoot);
  } catch (err) {
    // Fail-closed if the vault can't be opened — better to refuse a write than
    // pass a payload that contains unresolved tokens through to disk.
    emit(denyOutput(`scrim: vault unavailable (${(err as Error).message})`));
    return;
  }

  const { output, stats } = detokenize(input, vault);

  // Audit the restore. We log even when 0 tokens were touched? No — only when
  // we actually did work, to keep the log signal-heavy.
  if (stats.replaced > 0 || stats.missing.length > 0) {
    try {
      auditAppend(repoRoot, {
        ruleId: "detokenize",
        tool: input.tool_name ?? "Write",
        action: stats.missing.length > 0 ? "block" : "restore",
        context: {
          replaced: stats.replaced,
          missing: stats.missing.length,
        },
      });
    } catch {
      // Audit failures must not stop a write; log to stderr and continue.
      process.stderr.write("scrim-detokenize: audit append failed\n");
    }
  }

  emit(output);
}

try {
  main();
} catch (err) {
  emit({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `scrim: internal error (${(err as Error).message})`,
    },
  });
  process.stderr.write(`scrim-detokenize: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
}
