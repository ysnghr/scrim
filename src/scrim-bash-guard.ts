// PreToolUse hook for Bash.
//
// Compiled to bin/scrim-bash-guard.js. Inspects the command; denies with a
// safe_shell hint when the command is known to dump credentials or PII; passes
// through otherwise.

import { readFileSync } from "node:fs";
import { append as auditAppend } from "./audit/index.js";
import { decideBash, type HookInput, type HookOutput } from "./hooks/bash-guard.js";

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function emit(output: HookOutput): void {
  process.stdout.write(JSON.stringify(output));
}

function main(): void {
  const raw = readStdin();
  let input: HookInput;
  try {
    input = raw ? (JSON.parse(raw) as HookInput) : {};
  } catch {
    emit({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "scrim: malformed hook input",
      },
    });
    return;
  }

  const repoRoot = (input as HookInput & { cwd?: string }).cwd ?? process.cwd();
  const { output, matched } = decideBash(input);

  if (matched) {
    try {
      auditAppend(repoRoot, {
        ruleId: matched.id,
        tool: "Bash",
        action: "block",
        context: { reason: matched.why },
      });
    } catch {
      process.stderr.write("scrim-bash-guard: audit append failed\n");
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
  process.stderr.write(`scrim-bash-guard: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
}
