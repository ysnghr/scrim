// PreToolUse Stop hook.
//
// Compiled to bin/scrim-stop.js and registered in hooks/hooks.json. Claude Code
// fires this when the session ends. Wipes the on-disk vault unless the policy
// has vault.wipe_on_stop: false. Always exits 0 — a hook that blocks the agent
// from stopping would be worse than one that leaks a vault.

import { readFileSync } from "node:fs";
import { openVault } from "./vault/index.js";
import { loadPolicy } from "./policy/index.js";
import { append as auditAppend } from "./audit/index.js";

interface StopHookInput {
  cwd?: string;
}

interface StopHookOutput {
  continue?: boolean;
  hookSpecificOutput?: {
    hookEventName: "Stop";
    additionalContext?: string;
  };
}

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function emit(output: StopHookOutput): void {
  process.stdout.write(JSON.stringify(output));
}

function main(): void {
  const raw = readStdin();
  let input: StopHookInput = {};
  try {
    if (raw) input = JSON.parse(raw) as StopHookInput;
  } catch {
    // Malformed payload — still proceed; Stop must not block the agent.
  }
  const repoRoot = input.cwd ?? process.cwd();

  let wipeOnStop = true;
  try {
    wipeOnStop = loadPolicy(repoRoot).vault.wipeOnStop;
  } catch {
    // Policy unreadable: default to wipe (safer).
  }

  if (!wipeOnStop) {
    emit({ continue: true });
    return;
  }

  try {
    const vault = openVault(repoRoot);
    const sizeBefore = vault.size();
    vault.wipe();
    if (sizeBefore > 0) {
      try {
        auditAppend(repoRoot, {
          ruleId: "session_end",
          tool: "stop",
          action: "wipe",
          context: { entriesWiped: sizeBefore },
        });
      } catch {
        // best-effort
      }
    }
  } catch (err) {
    // Vault corrupt or unreadable. Still try to remove the files so the next
    // session starts clean. wipe() handles that case via best-effort unlinks
    // already, but if openVault threw before construction we can't call it —
    // log and move on.
    process.stderr.write(`scrim-stop: vault wipe failed: ${(err as Error).message}\n`);
  }

  emit({ continue: true });
}

try {
  main();
} catch (err) {
  process.stderr.write(`scrim-stop: ${(err as Error).stack ?? err}\n`);
  emit({ continue: true });
}
