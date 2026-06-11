# Scrim

**A context firewall for Claude Code.** Scrim keeps secrets and PII out of the model's context window without blocking the agent's work — it *redacts and reversibly tokenizes* sensitive content at the tool boundary, then restores the real values before anything is written back to disk.

> Permissions decide *which* files and commands the agent may touch. Scrim inspects *what's inside* everything that does pass through — and lets the agent keep working with a masked copy instead of failing the task.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()
[![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-blueviolet.svg)]()

---

## Table of contents

- [Why Scrim exists](#why-Scrim-exists)
- [How it's different](#how-its-different)
- [How it works](#how-it-works)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Detection engine](#detection-engine)
- [Security model](#security-model)
- [Limitations & honest caveats](#limitations--honest-caveats)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Scrim exists

Claude Code already has a permission system, and you *can* write a `deny` rule that stops the agent reading `.env`. That's necessary, but it's not enough — for four structural reasons:

1. **Permissions are all-or-nothing, by path.** Block `.env` and the agent can't use its safe parts (ports, regions, feature flags) either, so legitimate tasks fail. Allow it and the secret leaks. There is no "read, but mask the secret" — Scrim adds exactly that.
2. **Secrets and PII leak through far more than `.env`.** They show up in command output (`env`, `printenv`, `git remote -v` with tokens in URLs, `kubectl get secret -o yaml`, `docker inspect`, connection strings in stack traces, log files) and in files that aren't named `.env` (`config.json`, `*.tfvars`, `settings.py`, `*.pem`, test fixtures, seed CSVs). You cannot enumerate a deny rule for every path and every command. Content-based scanning doesn't care where the data came from.
3. **Permissions never look at content.** A deny rule is about *which* tool target, not *what's inside it*. Ten thousand customer emails in a query result sail straight through. Permissions have zero PII coverage.
4. **Permissions block; they don't redact, tokenize, reverse, share, or audit.** No reversible masking, no team-shared content policy, no record of what almost leaked.

**Mental model:** permissions are the *door lock* — which doors may open. Scrim is the *metal detector* on everything that passes through — and it lets people through after removing the weapon (redaction) instead of locking the door entirely.

---

## How it's different

There are already good tools in this space. Scrim is deliberately *not* a copy of any of them:

| | Network proxy redactors (e.g. local egress proxies) | MCP DLP gateways (commercial) | **Scrim** |
|---|---|---|---|
| Integration | Wraps API traffic via `HTTP_PROXY` / TLS interception | Hosted gateway in front of SaaS MCP servers | **Native Claude Code plugin** (MCP tools + hooks) |
| Keeps files correct | No — risks writing `[REDACTED]` into your files | N/A (read-only SaaS focus) | **Yes — reversible tokenization restores real values on write** |
| False-positive control | Generic regex | Vendor rulesets | **Repo-tuned: learns your keys, domains, ID formats** |
| Team policy | Per-user config | SaaS console | **Committable `.Scrim/policy.yml` in your repo** |
| Audit log | Basic local file | Cloud, paid | **Local, append-only, value-free** |
| License | Mixed | Proprietary | **MIT** |

The combination — Claude-Code-native + a reversible loop that never corrupts files + repo-tuned low false positives + a committable team policy + a local audit log — is what doesn't exist elsewhere. Each piece exists individually; the bundle doesn't.

---

## How it works

The core trick is a **reversible loop** so the agent stays fully functional while the model never sees a real secret.

### The killer scenario

1. The agent needs to refactor `config.yml`, which contains a real database password.
2. Scrim's `safe_read` tool reads the file, detects the password, and returns it with a stable token:
   ```yaml
   database:
     host: db.internal
     password: ⟦Scrim:db_password:a1b2c3⟧
   ```
3. The **model only ever sees the token.** It reasons about and rewrites the file normally.
4. When the agent writes the file back, a `PreToolUse` hook on `Write`/`Edit`/`MultiEdit` swaps the token back to the real password **before the bytes hit disk.**
5. The file on disk is byte-for-byte correct. The secret never entered the context window. Nothing was blocked.

Permissions cannot do this — they would block the read, and the task would fail.

### Where interception happens

- **Ingress (into context):** the agent uses Scrim's MCP tools (`safe_read`, `safe_grep`, `safe_shell`) instead of the native `Read`/`Bash`. The MCP server reads/executes itself, scrubs the result, and returns a tokenized copy. Native `Read`/`Bash` are `deny`-listed on sensitive globs so the agent is routed through Scrim.
- **Egress (back to disk):** a `PreToolUse` hook rewrites tool *input* on `Write`/`Edit`/`MultiEdit`, de-tokenizing any Scrim tokens back to their real values.
- **Token vault:** the token↔value map lives **only on your machine**, in memory plus an encrypted, session-scoped file. It is never sent to the API and never written to the audit log.

> **Design note.** Scrim intercepts ingress through replacement MCP tools rather than by rewriting native tool *output*, because at the time of writing Claude Code's `PreToolUse` hooks can reliably rewrite tool **input**, while rewriting an already-returned tool **output** is not a guaranteed capability across versions. The architecture is built on the mechanism that is documented and stable. See [Limitations](#limitations--honest-caveats).

---

## Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │                 Claude Code                  │
                          │                                              │
  agent calls safe_read ──┼──▶  Scrim MCP server                         │
                          │       │  1. read / exec on disk              │
                          │       │  2. detect (secrets + PII)           │
                          │       │  3. tokenize  ──▶  Token Vault (local)│
                          │       │  4. return masked content            │
                          │     ◀─┘                                      │
   model sees tokens  ◀───┼──── masked content (⟦Scrim:...⟧)             │
                          │                                              │
  agent writes file   ────┼──▶  PreToolUse hook (Write|Edit|MultiEdit)   │
                          │       └─ de-tokenize via Vault ──▶ real bytes │
                          │                                              │
                          │     all detections ──▶  Audit Log (local)    │
                          └─────────────────────────────────────────────┘

         Native Read / Bash on sensitive globs ──▶ DENIED (routes agent to Scrim)
```

**Components**

- `Scrim-mcp` — the MCP server exposing `safe_read`, `safe_grep`, `safe_shell`, and `Scrim_status`.
- `hooks/pre-write-detokenize` — `PreToolUse` hook that restores real values before writes.
- `hooks/pre-bash-guard` — `PreToolUse` hook that either routes risky commands through `safe_shell` or pipes their output through the redactor.
- `engine/` — detection (Gitleaks-compatible rules + Presidio + repo-tuned rules).
- `vault/` — local, ephemeral, encrypted token store. Fail-closed.
- `audit/` — append-only `detections.jsonl` (no secret values, only rule id + token ref + hash).
- `.Scrim/policy.yml` — committable team policy.

---

## Quick start

> **Status: alpha.** Validate behavior against your Claude Code version before relying on Scrim in a regulated environment.

### Build and load locally

```bash
git clone https://github.com/yasinughur/scrim
cd scrim
./scripts/install.sh            # npm install + npm run build
claude --plugin-dir "$(pwd)"    # loads scrim into Claude Code for this session
```

`scripts/install.sh` only builds; it never touches `~/.claude.json` or your
project settings. All plugin wiring lives inside the repo (`.claude-plugin/plugin.json`,
`.mcp.json`, `hooks/hooks.json`) and is picked up by `--plugin-dir`.

### Install as a Claude Code plugin (when a marketplace is available)

```bash
# Add the marketplace
/plugin marketplace add yasinughur/scrim

# Install
/plugin install scrim@scrim
```

### What gets registered

When the plugin is loaded, Claude Code sees:

- **MCP server** `scrim`, providing `safe_read`, `safe_grep`, `safe_shell`, and `scrim_status` (from `.mcp.json`).
- **PreToolUse hooks** on `Write|Edit|MultiEdit` (detokenize) and `Bash` (bash-guard) (from `hooks/hooks.json`).
- **Skill** `using-scrim` that steers the agent toward the `safe_*` tools when reading config-like files (from `skills/using-scrim/SKILL.md`).
- **Slash commands** `/scrim:status`, `/scrim:policy`, `/scrim:audit` (from `commands/`).

No edits to `~/.claude.json` are made. To add the recommended deny-list for native `Read`/`Bash`, paste this into your project's `.claude/settings.json`:

```jsonc
{
  "permissions": {
    "deny": [
      "Read(./.env*)", "Read(**/*.pem)", "Read(**/secrets/**)",
      "Bash(env)", "Bash(printenv*)", "Bash(*kubectl get secret*)"
    ]
  }
}
```

### Verify

```text
/scrim:status     # shows active rules, vault size, recent detections, hook health
```

---

## Configuration

Scrim reads `.Scrim/policy.yml` from your repo root. Commit it so the whole team shares one policy.

```yaml
version: 1

# What to do per data class: redact | block | alert | allow
actions:
  secrets: redact          # tokenize, restore on write
  pii_customer: redact
  pii_internal: alert      # log but pass through
  internal_hostnames: redact

# Detection sources
detection:
  gitleaks: true           # 100+ secret types, Gitleaks-compatible rules
  presidio: false          # PII via NER — accurate but adds latency; opt-in
  fast_pii_regex: true     # email / phone / card / SSN via regex (low latency)

# Repo-tuning: cut false positives by teaching Scrim your project
tune:
  env_keys_from: [".env.example"]      # treat these keys' values as secret
  internal_domains: ["*.internal", "*.corp.example.com"]
  custom_patterns:
    - name: customer_id
      regex: 'CUST-[0-9]{8}'
      class: pii_customer

# Safety
fail_closed: true          # if the engine errors, BLOCK rather than pass raw

# Allowlist: known-safe strings that look sensitive but aren't
allow:
  - "AKIAIOSFODNN7EXAMPLE"  # AWS docs example key
```

---

## Detection engine

- **Secrets** — Gitleaks-compatible rules cover 100+ credential types (cloud keys, tokens, private keys, connection strings). Bring your own custom patterns in `policy.yml`.
- **PII** — two tiers: a fast regex tier (email, phone, card, SSN) on by default, and an optional [Microsoft Presidio](https://github.com/microsoft/presidio) NER tier for names/addresses/freeform PII. Presidio is more accurate but adds latency, so it's opt-in.
- **Repo-tuning** — Scrim learns your project's own `.env` key names, internal domains, and ID formats to dramatically cut false positives. Over-redaction degrades the agent's reasoning, so tuning is a first-class feature, not an afterthought.

---

## Security model

- **Local-first.** Detection, tokenization, and the vault run entirely on your machine. No telemetry, no phone-home.
- **The vault is itself a secret store.** It is in-memory plus an encrypted session-scoped file, never transmitted, never logged. It is wiped on session end.
- **Fail-closed.** If the detection engine errors or the vault is unavailable, Scrim blocks rather than forwarding raw content. A security tool that fails open is worse than none.
- **Value-free audit.** `detections.jsonl` records rule id, tool, action, timestamp, and a token reference/hash — never the secret value itself.
- **Auditable config.** Scrim only writes to `.claude/settings.json` and `.Scrim/`. There is a known class of attacks where malicious hooks rewrite `~/.claude.json` to hijack MCP traffic; Scrim's installer prints a diff of every change it makes and touches nothing else.

---

## Limitations & honest caveats

This is alpha software and a security tool. Read this section.

- **Hook capability depends on your Claude Code version.** Scrim relies on `PreToolUse` input rewriting (documented and stable) for egress. If a future version reliably supports rewriting tool *output*, Scrim can simplify ingress to zero-friction interception of the native `Read`/`Bash` — until then it routes through replacement MCP tools. Run `/Scrim:status` to see what's active.
- **Routing friction.** Forcing the agent through `safe_read`/`safe_shell` works only if the native tools are denied on the right globs and the agent is steered (via the bundled `SKILL.md` and clear tool descriptions). A misconfigured deny list = a bypass.
- **False positives can break reasoning.** Aggressive redaction can strip context the agent needs. Tune with `policy.yml`; start narrow and widen.
- **Performance.** The Presidio PII tier can add seconds per scan. Default to the fast regex tier; enable NER only where you need it.
- **Not a guarantee.** No detector catches everything. Scrim reduces leakage substantially; it does not make leakage impossible. Treat it as defense-in-depth, alongside permissions and secret rotation — not a replacement.

---

## Roadmap

- [x] **Phase 0 — Validate** hook capabilities against current Claude Code (`PreToolUse` `hookSpecificOutput.updatedInput` confirmed for input rewriting).
- [x] **Phase 1 — MVP:** secrets + fast PII tier, file-read vector via `safe_read`, reversible loop end-to-end (`safe_read` → tokens → detokenize hook), local audit log. Verified by the killer-scenario integration test.
- [x] **Phase 2 — Coverage:** Bash/command output via `safe_shell` + `bash-guard`, repo-tuning (env keys, internal domains, custom patterns). Presidio NER bridge is wired but opt-in and untested end-to-end.
- [x] **Phase 3 — Team & distribution:** committable `.scrim/policy.yml`, slash commands (`/scrim:status`, `/scrim:policy`, `/scrim:audit`), plugin manifest ready for marketplace packaging.
- [ ] **Phase 4 — Differentiation:** compliance evidence export (SOC 2 / GDPR mapping), and prompt-injection detection on retrieved content (same choke point as redaction — a natural two-for-one).

---

## Development

```bash
npm install
npm run build       # compile src/ → bin/
npm test            # runs 76+ tests across engine, vault, audit, policy, MCP, hooks, e2e
npm run typecheck   # strict TS, no emit
```

The end-to-end test (`src/e2e/killer-scenario.test.ts`) spawns the real MCP server over stdio and the real detokenize hook over stdin/stdout — if it passes, the reversible loop is intact for your Node version.

---

## Contributing

Contributions welcome — especially detection rules, repo-tuning heuristics, and version-compatibility reports for new Claude Code releases. Please open an issue before large changes. Security-sensitive reports: see `SECURITY.md` for private disclosure.

---

## License

MIT — see [LICENSE](LICENSE).
