// Pure logic for the PreToolUse Bash hook.
//
// Walks the parsed shell AST of the command and denies known credential-leaking
// invocations regardless of quoting, escaping, wrapper layers (sudo / eval /
// bash -c / xargs / timeout), or command substitution. Regex-only detection in
// the previous implementation was trivially evaded by `'env'`, `\env`,
// `bash -c "env"`, etc.; this rewrite uses shell-quote to tokenize the command
// the way a shell would, then applies per-program rules to the argv of each
// segment.
//
// Hard limits: nested expansion (`eval $(echo env)`) and arbitrary $(...) that
// contains a non-direct invocation (`bash -c "$(cat foo)"` where foo is not in
// the command line) are out of scope. This is a guard rail, not a sandbox —
// the real DLP boundary is safe_shell's redaction of command output.

import { parse, type ParseEntry } from "shell-quote";

export interface HookInput {
  tool_name?: string;
  tool_input?: { command?: string } & Record<string, unknown>;
}

export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision?: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
  };
}

interface RiskyMatch {
  id: string;
  why: string;
}

type ArgMatcher = (argv: string[]) => RiskyMatch | null;

// Wrappers we transparently unwrap to inspect the real command underneath.
const SUDO_LIKE = new Set(["sudo", "doas", "nice", "nohup", "ionice", "stdbuf"]);
const SHELL_DASH_C = new Set(["bash", "sh", "zsh", "ksh", "dash", "busybox"]);
const EVAL_LIKE = new Set(["eval"]);

function alwaysRisky(id: string, why: string): ArgMatcher {
  return () => ({ id, why });
}

function procEnvironMatcher(_argv: string[]): RiskyMatch | null {
  for (const a of _argv.slice(1)) {
    if (/^\/proc\/[^/]+\/environ\b/.test(a)) {
      return {
        id: "proc-environ",
        why: "/proc/*/environ exposes a process's environment, which routinely includes credentials",
      };
    }
  }
  return null;
}

// Per-program rules. Receive the full argv (cmd at [0]); return a RiskyMatch
// when the command is risky, or null otherwise.
const RULES: Record<string, ArgMatcher> = {
  env: alwaysRisky(
    "env-dump",
    "`env` dumps every environment variable, which routinely includes credentials",
  ),
  printenv: alwaysRisky(
    "printenv",
    "`printenv` prints environment variables, which routinely include credentials",
  ),
  set: (argv) => {
    // `set` (no args) and `set --` dump every shell variable. `set -e`, `set -o`,
    // `+x`, etc. configure shell options and are fine.
    if (argv.length === 1) {
      return { id: "set-dump", why: "`set` with no args dumps shell variables, which can include secrets" };
    }
    if (argv[1] === "--") {
      return { id: "set-dump", why: "`set --` resets positional params and dumps variables" };
    }
    return null;
  },
  kubectl: (argv) => {
    const VERBS = new Set(["get", "describe", "edit", "view"]);
    if (argv.length >= 3 && VERBS.has(argv[1] ?? "")) {
      for (const a of argv.slice(2)) {
        if (a === "secret" || a === "secrets") {
          return { id: "kubectl-secret", why: "kubectl can return decoded secrets in stdout" };
        }
      }
    }
    return null;
  },
  docker: (argv) => {
    if (argv[1] === "inspect") {
      return { id: "docker-inspect", why: "`docker inspect` includes environment variables and bind mounts" };
    }
    // `docker compose config` (modern subcommand form) — different program name
    // is also handled below under "docker-compose" for the legacy form.
    if (argv[1] === "compose" && argv[2] === "config") {
      return {
        id: "docker-compose-config",
        why: "`docker compose config` prints the resolved environment, including secrets",
      };
    }
    return null;
  },
  "docker-compose": (argv) => {
    if (argv[1] === "config") {
      return {
        id: "docker-compose-config",
        why: "`docker-compose config` prints the resolved environment, including secrets",
      };
    }
    return null;
  },
  git: (argv) => {
    if (argv[1] === "remote" && /^(?:-v|--verbose|show)$/.test(argv[2] ?? "")) {
      return {
        id: "git-remote-v",
        why: "remote URLs can contain embedded credentials (https://user:token@host)",
      };
    }
    return null;
  },
  aws: (argv) => {
    if (argv[1] === "configure") {
      return { id: "aws-configure", why: "`aws configure` reads/writes credentials at ~/.aws/credentials" };
    }
    return null;
  },
  gcloud: (argv) => {
    if (argv[1] === "auth" && /^print-(access|identity)-token$/.test(argv[2] ?? "")) {
      return { id: "gcloud-print-token", why: "this command prints a bearer token directly to stdout" };
    }
    return null;
  },
  cat: procEnvironMatcher,
  less: procEnvironMatcher,
  more: procEnvironMatcher,
  head: procEnvironMatcher,
  tail: procEnvironMatcher,
  bat: procEnvironMatcher,
};

function stripLeadingBackslash(s: string): string {
  // `\env` is the backslash-escape evasion; the shell interprets it as `env`.
  return s.startsWith("\\") ? s.slice(1) : s;
}

function checkArgv(argv: string[]): RiskyMatch | null {
  if (argv.length === 0) return null;
  const head = stripLeadingBackslash(argv[0] ?? "");
  const rule = RULES[head];
  if (rule) {
    const m = rule([head, ...argv.slice(1)]);
    if (m) return m;
  }

  if (SUDO_LIKE.has(head)) {
    // sudo / doas / nice / nohup: drop their own flags, then the rest is the
    // wrapped command. We tolerate sudo's flag-value pairs (-u user, etc.) by
    // skipping any token starting with `-` and its value when a short flag like
    // `-u` is followed by a non-flag.
    let i = 1;
    while (i < argv.length && argv[i]!.startsWith("-")) {
      const flag = argv[i]!;
      const takesValue = /^-[uUgH]$/.test(flag) || /^--(user|group|host|prompt)$/.test(flag);
      i++;
      if (takesValue && i < argv.length && !argv[i]!.startsWith("-")) i++;
    }
    if (i < argv.length) return checkArgv(argv.slice(i));
  }

  if (SHELL_DASH_C.has(head)) {
    // bash -c 'COMMAND'  /  sh -c "COMMAND"
    const ci = argv.indexOf("-c");
    if (ci >= 0 && argv.length > ci + 1) {
      return decideCommand(argv[ci + 1] ?? "");
    }
  }

  if (EVAL_LIKE.has(head)) {
    // `eval foo bar` — concatenate remaining args with a space and re-parse.
    if (argv.length > 1) {
      return decideCommand(argv.slice(1).join(" "));
    }
  }

  if (head === "xargs") {
    // Skip xargs's own flags then the trailing tokens are the wrapped command.
    let i = 1;
    while (i < argv.length && argv[i]!.startsWith("-")) {
      // Some xargs flags take a value: -I REPL, -L NUM, -n NUM, -P NUM.
      const flag = argv[i]!;
      const takesValue = /^-[ILnPI]$/.test(flag);
      i++;
      if (takesValue && i < argv.length && !argv[i]!.startsWith("-")) i++;
    }
    if (i < argv.length) return checkArgv(argv.slice(i));
  }

  if (head === "timeout") {
    // timeout [opts] DURATION CMD [ARGS]
    let i = 1;
    while (i < argv.length && argv[i]!.startsWith("-")) {
      const flag = argv[i]!;
      const takesValue = /^-[sk]$/.test(flag) || /^--(signal|kill-after)$/.test(flag);
      i++;
      if (takesValue && i < argv.length && !argv[i]!.startsWith("-")) i++;
    }
    if (i < argv.length) i++; // skip duration
    if (i < argv.length) return checkArgv(argv.slice(i));
  }

  return null;
}

// Pull `$(...)` and `` `...` `` payloads out of a token. shell-quote with a
// function-form `env` passes substitutions through as raw substrings; we recurse
// on the inner command. Nested substitutions are handled by re-applying this
// to whatever shell-quote produces on the inner parse.
function extractCommandSubstitutions(s: string): string[] {
  const out: string[] = [];
  // $( ... )  — allow a single nested layer of parens to survive without
  // breaking the regex. Deeper nesting is rare and falls through harmlessly.
  const dollar = /\$\(((?:[^()]|\([^)]*\))*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = dollar.exec(s)) !== null) out.push(m[1] ?? "");
  // ` ... `
  const back = /`([^`]*)`/g;
  while ((m = back.exec(s)) !== null) out.push(m[1] ?? "");
  return out;
}

function decideCommand(command: string): RiskyMatch | null {
  if (!command.trim()) return null;

  let parsed: ParseEntry[];
  try {
    // Function-form env so $VAR references survive as empty strings rather
    // than throwing or expanding to literal text from process.env.
    parsed = parse(command, () => undefined);
  } catch {
    return regexFallback(command);
  }

  // Split on operators into command segments. ;  &&  ||  |  &  |&  ;;  (  )
  // are all segment boundaries; redirects are not.
  const segments: ParseEntry[][] = [[]];
  for (const entry of parsed) {
    if (typeof entry === "object" && "op" in entry) {
      const op = entry.op;
      if (
        op === ";" || op === "&&" || op === "||" ||
        op === "|" || op === "&"  || op === "|&" ||
        op === ";;" || op === "(" || op === ")"
      ) {
        segments.push([]);
        continue;
      }
    }
    segments[segments.length - 1]!.push(entry);
  }

  for (const seg of segments) {
    const argv: string[] = [];
    for (const e of seg) {
      if (typeof e === "string") {
        // shell-quote keeps $(...) and backticks inside string tokens. Recurse
        // into each substitution body first; if anything in there matches,
        // surface that.
        for (const sub of extractCommandSubstitutions(e)) {
          const m = decideCommand(sub);
          if (m) return m;
        }
        argv.push(e);
      } else if (typeof e === "object" && "pattern" in e) {
        argv.push(e.pattern);
      }
      // comments are ignored
    }
    const m = checkArgv(argv);
    if (m) return m;
  }
  return null;
}

// Final fallback for inputs shell-quote can't parse. Mirrors the pre-AST rule
// set so we don't widen the security boundary on parser failure.
function regexFallback(command: string): RiskyMatch | null {
  const RISKY = [
    { id: "env-dump", re: /(?:^|[\s;&|`(])env(?:\s|$|\||;|&|`|\))/, why: "`env` dumps every environment variable, which routinely includes credentials" },
    { id: "printenv", re: /(?:^|[\s;&|`(])printenv\b/, why: "`printenv` prints environment variables, which routinely include credentials" },
    { id: "kubectl-secret", re: /kubectl\s+(?:get|describe|edit|view)\s+secret/i, why: "kubectl can return decoded secrets in stdout" },
    { id: "docker-inspect", re: /docker\s+inspect\b/i, why: "`docker inspect` includes environment variables and bind mounts" },
    { id: "docker-compose-config", re: /docker[- ]compose\s+config\b/i, why: "`docker compose config` prints the resolved environment, including secrets" },
    { id: "git-remote-v", re: /git\s+remote\s+(?:-v|--verbose|show)\b/i, why: "remote URLs can contain embedded credentials" },
    { id: "aws-configure", re: /aws\s+configure\b/i, why: "`aws configure` reads/writes credentials at ~/.aws/credentials" },
    { id: "gcloud-print-token", re: /gcloud\s+auth\s+(?:print-access-token|print-identity-token)/i, why: "this command prints a bearer token directly to stdout" },
  ];
  for (const r of RISKY) {
    if (r.re.test(command)) return { id: r.id, why: r.why };
  }
  return null;
}

export interface BashGuardDecision {
  output: HookOutput;
  matched?: { id: string; why: string };
}

export function decideBash(input: HookInput): BashGuardDecision {
  const command = input.tool_input?.command ?? "";
  if (!command) {
    return {
      output: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } },
    };
  }
  const m = decideCommand(command);
  if (m) {
    return {
      output: {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason:
            `scrim: ${m.why}. Use scrim's safe_shell tool instead — it runs the same` +
            ` command but redacts secrets and PII from the output before the model sees it.`,
        },
      },
      matched: { id: m.id, why: m.why },
    };
  }
  return {
    output: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } },
  };
}
