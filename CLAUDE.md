# CLAUDE.md

Working notes for Claude Code agents editing this repo. Not a user-facing doc — that's the README.

## What this repo is

A Claude Code plugin that puts a redaction firewall in front of the model. The
core invariant is the **reversible loop**: ingress tools (`safe_read`, `safe_grep`,
`safe_shell`) replace secrets with `⟦scrim:class:id⟧` tokens before they enter
context, and a `PreToolUse` hook on `Write|Edit|MultiEdit` restores the real
values before bytes hit disk. The model never sees a raw secret; files stay
byte-correct.

If a change you're about to make breaks the loop, it's wrong.

## Mental model (one sentence per layer)

```
agent  ──safe_read──▶  MCP server  ──┐
                                     ├──▶ engine (detect spans)
                                     ├──▶ policy (per-class action)
                                     ├──▶ vault (mint stable tokens)
                                     └──▶ audit (value-free entries)
                                          │
                       masked content ◀───┘

agent  ──Write──▶  detokenize hook  ──vault.resolve──▶  real bytes to disk
agent  ──Bash───▶  bash-guard hook  ──risky? deny with safe_shell hint
```

The MCP server and each hook are **separate processes**. The vault lives on
disk because of that — no shared memory between them.

## Hard invariants (don't violate)

1. **Fail-closed.** Engine error, vault unreadable, missing token in a write
   payload, audit-write failure on the secret path — refuse the tool call.
   Never silently fall back to passing raw content.
2. **Value-free audit.** The `AuditEntry` type doesn't have a `value` field and
   `sanitize()` in `src/audit/index.ts` strips any extra keys defensively.
   Don't add a `value` field. If you need to correlate, use `valueHash` from
   `hashValue()` — salted sha256 prefix, not reversible.
3. **Cross-process vault is on disk.** Atomic-rename writes only. `openVault`
   may be called from the MCP server *or* a hook. Don't add in-memory-only
   state that the hooks need.
4. **Class vs rule id.** `span.class` is the *policy bucket* (e.g. `"secrets"`,
   `"pii_customer"`) — that's what `actionFor(policy, klass)` consults to pick
   redact/block/alert/allow. `span.ruleId` is the *specific detector* (e.g.
   `"aws-access-key-id"`) — that's what becomes the visible slug in the token
   `⟦scrim:<ruleId>:<id>⟧`. They are different on purpose. Don't conflate.
5. **Span merge is tier-priority, not length-priority.** See
   `mergeSpans` in `src/engine/spans.ts`. Secrets must never lose to a
   coincidentally-overlapping PII match (e.g. the email regex matches
   `password@host` inside a URL). If you add a class, add it to
   `CLASS_PRIORITY` above PII.
6. **Hook output schema.** Use `hookSpecificOutput.permissionDecision` for
   allow/deny and `hookSpecificOutput.updatedInput` to rewrite tool input.
   Don't use the deprecated top-level `decision` field.

## Repo layout

```
.claude-plugin/plugin.json   plugin manifest, namespace `scrim`
.mcp.json                    registers the MCP server at bin/scrim-mcp.js
hooks/hooks.json             PreToolUse wiring for Write|Edit|MultiEdit + Bash
skills/using-scrim/SKILL.md  model-invoked steering toward safe_* tools
commands/*.md                /scrim:status, /scrim:policy, /scrim:audit

src/scrim-mcp.ts             entrypoint → bin/scrim-mcp.js
src/scrim-detokenize.ts      entrypoint → bin/scrim-detokenize.js
src/scrim-bash-guard.ts      entrypoint → bin/scrim-bash-guard.js
src/tokens.ts                ⟦scrim:class:id⟧ format helpers
src/engine/                  detection (secrets, pii, tuned, presidio) + spans
src/vault/                   AES-256-GCM session vault on disk
src/audit/                   .scrim/audit/detections.jsonl writer
src/policy/                  YAML loader + validator
src/mcp/                     context, processText pipeline, tool handlers
src/hooks/                   pure detokenize + bash-guard logic
src/e2e/                     killer-scenario test (real subprocess stdio)

policy/default-policy.yml    schema reference for users
scripts/install.sh           npm install + npm run build (does NOT touch ~/.claude)
```

Tests live next to the code they exercise as `*.test.ts`.

## Common tasks

### Add a new secret rule

1. Add an entry to `SECRET_RULES` in `src/engine/rules/secrets-rules.ts`.
   - Capture group 1 = the secret value (not the surrounding context).
   - Set `entropy` if the pattern is loose enough to need a placeholder filter.
2. Add a test in `src/engine/engine.test.ts` that asserts the rule fires and
   one that asserts it doesn't on an obvious false positive.
3. `npm test`.

### Add a new MCP tool

1. Add a handler in `src/mcp/tools.ts`. For any ingress tool, route results
   through `processText(text, "tool_name", ctx)` — that one call wires detect,
   policy action, vault, and audit.
2. Register it in `src/scrim-mcp.ts` with a Zod input schema. Description
   should tell the agent *when* to prefer it over native tools.
3. Add an integration test in `src/mcp/mcp.test.ts`.

### Add a new risky Bash pattern

1. Append to `RISKY` in `src/hooks/bash-guard.ts`. The `re` must be specific
   enough to not match lookalikes (`envoy`, `$environment`). Use boundary
   anchors like `(?:^|[\s;&|`(])`.
2. Add the command to the `denied` array in the bash-guard test, and a
   lookalike to the `does NOT deny` array.

### Change the policy schema

1. Update the `Policy` interface in `src/policy/index.ts`.
2. Update `defaultPolicy()` and `policy/default-policy.yml` together — they
   must mirror each other.
3. Update `validate()` to accept the new field and emit a per-field error path.
4. Update `toEngineInput()` if the engine consumes the new field.
5. Bump tests in `src/policy/policy.test.ts`.

## Code conventions

- **NodeNext ESM.** Relative imports in `src/` use `.js` extensions even in
  `.ts` source (TS resolves through to the source, tsc emits the .js).
- **strict + noUncheckedIndexedAccess.** Array/record reads are typed
  `T | undefined`. Use `arr[i]!` when you've just length-checked, or `?? default`.
- **No comments explaining what the code does.** Comments belong on
  non-obvious *why* — invariants, gotchas, design decisions. Most files have
  a short top-of-file block; keep that pattern.
- **Pure logic separate from process entrypoints.** Hooks: `src/hooks/*.ts`
  is testable, `src/scrim-*.ts` is the thin stdin/stdout shell. Same split
  for the engine and the MCP layer.
- **No new dependencies without a clear reason.** Current deps: MCP SDK,
  yaml, zod. Everything else is `node:`-prefix built-ins.

## Testing

```bash
npm test          # build + node --test bin/**/*.test.js
npm run typecheck # strict TS, no emit
npm run build     # tsc -p .
```

Patterns used here:

- **Pure modules** are tested via imports. Each test gets a fresh temp dir
  via `mkdtempSync(join(tmpdir(), "scrim-XYZ-"))`.
- **Entrypoint scripts** are tested via `spawnSync("node", [BIN], { input })`
  to verify the actual stdin/stdout JSON contract.
- **The e2e test** in `src/e2e/killer-scenario.test.ts` boots the MCP server
  as a child process and speaks JSON-RPC over its stdio. If it passes, the
  reversible loop is intact end-to-end.

When a test fails because two detectors fight (e.g. a URL password is
clobbered by the email regex), the fix usually lives in `CLASS_PRIORITY` or
in a more specific rule — not in the test.

## Hook protocol cheatsheet

PreToolUse input on stdin (only the fields we touch):
```json
{ "tool_name": "Write", "tool_input": { ... }, "cwd": "/path/to/repo" }
```

Pass through unchanged:
```json
{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow" } }
```

Rewrite tool input:
```json
{ "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": { ...new tool_input... },
    "permissionDecisionReason": "..."
} }
```

Deny:
```json
{ "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "..."
} }
```

Exit 0 in all of the above. Exit non-zero only for unrecoverable internal errors.

## Gotchas that bit us

- TS NodeNext + `.ts` imports → "allowImportingTsExtensions" errors. Use `.js`
  in source. We're not using `rewriteRelativeImportExtensions`.
- The email regex was clobbering URL-basic-auth passwords (`user:pass@host`
  contains a plausible email pattern). Solved with `CLASS_PRIORITY` in
  `mergeSpans`, not by tightening the email regex (which has other valid uses).
- `tokenize(value, klass)` second arg was originally `span.class` ("secrets")
  — fixed to `span.ruleId` ("aws-access-key-id") because the README example
  shows the specific rule, and that's what's informative to the agent.
- POSIX `appendFileSync` is atomic only below PIPE_BUF (~4 KiB). The audit
  writer caps each line and throws above the limit; don't raise the cap
  without switching to a lock.
- The Claude Code MCP server runs as a single long-lived process per session,
  but the hooks are spawned fresh for every Write/Bash. Anything they need
  must be on disk or in env.
