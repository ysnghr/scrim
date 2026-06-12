<p align="center">
  <img src=".github/assets/scrim-banner-dark.svg" alt="Scrim" width="100%">
</p>

<h1 align="center">Scrim</h1>

<p align="center">
  <b>A context firewall for Claude Code.</b><br/>
  Keep secrets and PII out of the model's context — without breaking the agent's work.
</p>

<p align="center">
  <a href="LICENSE.md"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange.svg">
  <img alt="Claude Code plugin" src="https://img.shields.io/badge/Claude%20Code-plugin-blueviolet.svg">
  <img alt="Tests" src="https://img.shields.io/badge/tests-193%20passing-brightgreen.svg">
</p>

<p align="center">
  <a href="#-how-it-works">How it works</a> •
  <a href="#-quick-start">Quick start</a> •
  <a href="#-what-gets-detected">Detection</a> •
  <a href="#-configuration">Configuration</a> •
  <a href="#-security-model">Security</a> •
  <a href="#-faq">FAQ</a>
</p>

---

## The 30-second pitch

Permissions decide **which** files the agent may touch. Scrim inspects **what's inside** everything that passes through — and lets the agent keep working with a masked copy instead of failing the task.

```diff
- password: "hunter2-real-prod-credential"
+ password: ⟦scrim:db-password:a1b2c3⟧
```

The model sees the token. The file on disk keeps the real value. Nothing leaks; nothing breaks.

---

## 🧠 How it works

Scrim wraps every sensitive read with a **reversible loop**: detect → tokenize on the way in, detokenize on the way out. The model only ever sees tokens. Files stay byte-correct.

### The reversible loop

```mermaid
sequenceDiagram
    autonumber
    actor Agent
    participant MCP as Scrim MCP server
    participant Engine as Detection engine
    participant Vault as Token vault (disk)
    participant Hook as Detokenize hook
    participant Disk as Your files

    Agent->>MCP: safe_read("config.yml")
    MCP->>Disk: read file
    Disk-->>MCP: raw bytes (contains real secret)
    MCP->>Engine: detect spans
    Engine-->>MCP: [{class:"secrets", value:"hunter2..."}]
    MCP->>Vault: mint token ⟦scrim:db-password:a1b2c3⟧
    MCP-->>Agent: masked content with tokens
    Note over Agent: model reasons over<br/>tokens, never the secret

    Agent->>Hook: Write(file, content-with-tokens)
    Hook->>Vault: resolve each ⟦scrim:...⟧
    Vault-->>Hook: real values
    Hook->>Disk: write real bytes
    Note over Disk: file is byte-correct
```

The loop has **two halves in two processes** that share state through an encrypted on-disk vault — so the MCP server (ingress) and the `PreToolUse` hook (egress) can be invoked independently and still close the loop.

### Architecture at a glance

```mermaid
flowchart LR
    subgraph CC["Claude Code"]
        Agent([Agent / model])
    end

    subgraph Scrim["Scrim plugin"]
        direction TB
        MCP["MCP server<br/>safe_read · safe_grep · safe_shell"]
        Hooks["PreToolUse hooks<br/>detokenize · bash-guard"]
        subgraph State["Local state"]
            Vault[("🔒 Encrypted<br/>token vault")]
            Audit[("📓 Value-free<br/>audit log")]
        end
        Engine["Detection engine<br/>secrets · PII · repo-tuned"]
    end

    Disk[("📁 Your repo")]

    Agent -- "ingress (read/grep/shell)" --> MCP
    Agent -- "egress (Write/Edit/Bash)" --> Hooks
    MCP --> Engine
    Engine --> Vault
    MCP --> Audit
    MCP <--> Disk
    Hooks <--> Vault
    Hooks <--> Disk
    MCP -. "masked content" .-> Agent
    Hooks -. "deny risky cmds" .-> Agent

    classDef store fill:#1f2937,stroke:#6b7280,color:#fff
    class Vault,Audit,Disk store
```

**Three moving parts, one invariant:**

| Component | Role | Where |
|---|---|---|
| **MCP tools** | Intercept reads/greps/shell output, return tokenized copy | `src/mcp/` |
| **Detokenize hook** | `PreToolUse` on `Write\|Edit\|MultiEdit` — restore real bytes before disk write | `src/hooks/detokenize.ts` |
| **Bash guard** | `PreToolUse` on `Bash` — deny risky commands, suggest `safe_shell` | `src/hooks/bash-guard.ts` |

> **Invariant:** if a change breaks the round-trip (read → token → write → byte-correct file), it's wrong.

---

## 🚀 Quick start

### 1. Install

```bash
git clone https://github.com/yasinughur/scrim
cd scrim
./scripts/install.sh           # npm install + npm run build
```

### 2. Wire it into Claude Code

```bash
claude --plugin-dir "$(pwd)"   # loads scrim for this session
```

This auto-registers (from the repo's manifests — no edits to `~/.claude.json`):

- 🔧 MCP server `scrim` → `safe_read`, `safe_grep`, `safe_shell`, `scrim_status`
- 🪝 `PreToolUse` hooks → detokenize on writes, guard on `Bash`
- 🎯 Skill `using-scrim` → steers the agent toward `safe_*` tools
- ⌨️ Slash commands → `/scrim:status`, `/scrim:policy`, `/scrim:audit`, `/scrim:doctor`

### 3. Route sensitive paths through Scrim

```bash
./scripts/install-deny-rules.sh   # merges recommended deny rules into .claude/settings.json
```

This denies the **native** `Read` and `Bash` on `.env*`, `*.pem`, `secrets/**`, `env`, `printenv`, etc. — forcing the agent through `safe_read` / `safe_shell` where Scrim can see the content.

### 4. Verify

```text
/scrim:doctor      # checks hooks, MCP server, vault, deny rules
/scrim:status      # shows active rules, recent detections, vault size
```

---

## 🔍 What gets detected

```mermaid
flowchart TD
    Text["Tool output / file content"] --> Pipeline

    subgraph Pipeline["Detection pipeline"]
        direction TB
        S["Secrets<br/>55+ vendor rules + entropy catchall"]
        P["PII (fast regex)<br/>email · phone · card · SSN"]
        N["PII (Presidio, opt-in)<br/>names · locations · freeform"]
        T["Repo-tuned<br/>your .env keys · domains · IDs"]
    end

    Pipeline --> Merge["Tier-priority merge<br/>secrets > hostnames > PII"]
    Merge --> Policy{Policy action}
    Policy -->|redact| Tok["Mint token<br/>⟦scrim:rule:id⟧"]
    Policy -->|block| Deny["Refuse tool call"]
    Policy -->|alert| Log["Log only, pass through"]
    Policy -->|allow| Pass["Pass through"]
```

| Tier | What | Latency | Default |
|---|---|---|---|
| **Secrets** | Cloud keys, source-forge tokens, payment APIs, SaaS, AI providers, observability, private-key blocks, URL basic-auth, generic `password=` with entropy gate + placeholder/shape filters | µs | ✅ on |
| **Fast PII** | Email, phone, credit card (Luhn), SSN | µs | ✅ on |
| **Presidio NER** | Person names, locations, freeform PII via spaCy | seconds | ❌ opt-in |
| **Repo-tuned** | Keys named in your `.env.example`, internal domain globs, your custom regex patterns | µs | ✅ on |

**Tier-priority merge** ensures that when two regexes claim overlapping bytes (e.g. an email regex matching `user@host` inside a basic-auth URL), the higher-tier class wins — secrets never lose to a coincidental PII match.

### Enabling Presidio (optional)

```bash
./scripts/install-presidio.sh    # provisions .scrim/presidio-venv with the analyzer
```

```yaml
# .scrim/policy.yml
detection:
  presidio: true
  presidio_command: /abs/path/to/.scrim/presidio-venv/bin/scrim-presidio
```

Presidio is **fail-soft**: a missing sidecar returns no spans rather than failing the tool call. Scrim consumes only `{start, end, entity_type}` triples — raw text never round-trips through Presidio's output, so a compromised sidecar can under-detect but cannot inject content into the model's context.

---

## ⚙️ Configuration

Scrim reads `.scrim/policy.yml` from your repo root. **Commit it** so the whole team shares one policy.

```yaml
version: 1

# What to do per data class: redact | block | alert | allow
actions:
  secrets:            redact      # tokenize, restore on write
  pii_customer:       redact
  pii_internal:       alert       # log but pass through
  internal_hostnames: redact

detection:
  gitleaks:       true            # 55+ vendor rules + entropy-gated catchall
  fast_pii_regex: true            # email / phone / card / SSN
  presidio:       false           # NER tier (opt-in, see above)
  entropy:
    generic_credential: 2.7       # lower = more recall, more FPs

# Cut false positives by teaching Scrim about your project
tune:
  env_keys_from:    [".env.example"]
  internal_domains: ["*.internal", "*.corp.example.com"]
  custom_patterns:
    - name:  customer_id
      regex: 'CUST-[0-9]{8}'
      class: pii_customer

fail_closed: true                 # if the engine errors, BLOCK, never pass raw

allow:                            # known-safe lookalikes
  - "AKIAIOSFODNN7EXAMPLE"        # AWS docs example key
```

See [`policy/default-policy.yml`](policy/default-policy.yml) for the full schema.

---

## 🛡️ Security model

| Property | Guarantee |
|---|---|
| **Local-first** | Detection, tokenization, vault — all on your machine. No telemetry. No phone-home. |
| **Fail-closed** | Engine error, vault unreadable, missing token, audit write failure → tool call is **refused**, never passed through raw. |
| **Value-free audit** | `detections.jsonl` records rule id, tool, action, timestamp, salted hash. **Never the secret value** — it's structurally impossible (the type has no `value` field). |
| **Encrypted vault** | AES-256-GCM on disk, atomic-rename writes. Cleared on session end. |
| **Cross-process by design** | MCP server and hooks are separate processes that share state via the vault — so each can be invoked independently and the loop still closes. |
| **Auditable installer** | Touches only `.claude/settings.json` and `.scrim/`. Prints a diff before every change. Never edits `~/.claude.json`. |

> **Why fail-closed matters.** A security tool that fails open is worse than none — it gives you the *belief* of protection without the protection. Scrim refuses rather than degrades.

---

## ❓ FAQ

<details>
<summary><b>Won't the agent get confused by tokens?</b></summary>

No — tokens use `⟦scrim:rule-id:short-id⟧` shaped delimiters (U+27E6/U+27E7). LLMs tokenize them as a single unit, they're vanishingly rare in real source, and they survive shells/JSON/YAML untouched. The agent reasons about them as opaque placeholders, exactly as intended.
</details>

<details>
<summary><b>What if the agent tries to bypass <code>safe_read</code> and calls <code>Read</code> directly?</b></summary>

That's exactly what the deny rules from `install-deny-rules.sh` are for — they make native `Read`/`Bash` *refuse* on sensitive globs, so the agent's only path forward is `safe_read`/`safe_shell`. Run `/scrim:doctor` to confirm the deny rules are in place.
</details>

<details>
<summary><b>Why MCP tools instead of rewriting native tool output?</b></summary>

At the time of writing, Claude Code's `PreToolUse` hooks can reliably rewrite tool **input** (so `Write` egress is solid), but rewriting an already-returned tool **output** isn't guaranteed across versions. Scrim is built on the mechanism that's documented and stable. If output-rewriting becomes a stable capability, ingress simplifies to zero-friction interception.
</details>

<details>
<summary><b>What about large files?</b></summary>

`safe_read` reads up to `detection.max_bytes` (default 10 MB) fully and returns redacted content. Above that, it switches to a chunked streaming scan and returns a per-rule summary (counts, lines, token refs) without the file body — call again with `byteRange: [start, end)` for a specific slice. The 16 KB streaming overlap bounds the longest single match the streaming path can catch; PEM blocks and JWTs fit comfortably.
</details>

<details>
<summary><b>How is this different from Gitleaks or Presidio?</b></summary>

Gitleaks and Presidio are *detectors* — they tell you something matches a pattern. Scrim is a **firewall**: it detects, reversibly tokenizes, lets the agent keep working, then restores. Gitleaks rules and Presidio NER are *inputs* to Scrim's engine, not competitors.
</details>

<details>
<summary><b>Is this a guarantee no secret will ever leak?</b></summary>

No. No detector catches everything. Scrim reduces leakage substantially; it does not make leakage impossible. Treat it as defense-in-depth, alongside permissions and secret rotation — not a replacement.
</details>

---

## 🆚 How it's different

|  | Network proxy redactors | Commercial MCP DLP gateways | **Scrim** |
|---|---|---|---|
| Integration | `HTTP_PROXY` / TLS interception | Hosted gateway in front of SaaS MCP | **Native Claude Code plugin** |
| Keeps files byte-correct | ❌ writes `[REDACTED]` | N/A (read-only SaaS) | ✅ **reversible tokenization** |
| False-positive control | Generic regex | Vendor rulesets | ✅ **repo-tuned** |
| Team policy | Per-user config | SaaS console | ✅ **committable `.scrim/policy.yml`** |
| Audit log | Basic local file | Cloud, paid | ✅ **local, append-only, value-free** |
| License | Mixed | Proprietary | ✅ **MIT** |

The bundle — Claude-Code-native + reversible loop + repo-tuned + committable policy + local audit — is what doesn't exist elsewhere. Each piece exists individually; the combination doesn't.

---

## 🗺️ Roadmap

- [x] **Phase 0 — Validate** hook capabilities against Claude Code (`PreToolUse` input rewriting confirmed)
- [x] **Phase 1 — MVP** secrets + fast PII, reversible loop end-to-end, local audit log
- [x] **Phase 2 — Coverage** Bash/command output via `safe_shell`, repo-tuning, Presidio bridge
- [x] **Phase 3 — Team & distribution** committable policy, slash commands, plugin manifest
- [ ] **Phase 4 — Differentiation** compliance evidence export (SOC 2 / GDPR mapping), prompt-injection detection on retrieved content

---

## 🧪 Development

```bash
npm install
npm run build       # compile src/ → bin/
npm test            # 193 tests: engine, vault, audit, policy, MCP, hooks, e2e
npm run typecheck   # strict TS, no emit
npm run bench       # synthetic-corpus detection benchmarks
```

The end-to-end test ([`src/e2e/killer-scenario.test.ts`](src/e2e/killer-scenario.test.ts)) spawns the real MCP server over stdio and the real detokenize hook over stdin/stdout. If it passes, the reversible loop is intact for your Node version.

---

## ⚠️ Limitations

> This is alpha software and a security tool. Read this.

- **Hook capability is version-dependent.** Scrim relies on `PreToolUse` input rewriting. Run `/scrim:doctor` to confirm it's active on your Claude Code build.
- **Routing friction.** Forcing the agent through `safe_*` works only if native `Read`/`Bash` are denied on the right globs. A misconfigured deny list = a bypass. `install-deny-rules.sh` is the safe path.
- **False positives can hurt reasoning.** Over-redaction strips context the agent needs. Tune `policy.yml` — start narrow, widen as needed.
- **Presidio adds latency.** Default to the fast regex tier; enable NER only where you actually need names/locations.
- **Not a guarantee.** Defense-in-depth alongside permissions and rotation. Not a replacement.

---

## 🤝 Contributing

Contributions welcome — especially:

- **Detection rules** in [`src/engine/rules/`](src/engine/rules/) (add a rule + a positive test + a false-positive test)
- **Repo-tuning heuristics** that further cut FPs without hurting recall
- **Version-compatibility reports** for new Claude Code releases

Please open an issue before large changes. Security-sensitive reports: see [`SECURITY.md`](SECURITY.md) for private disclosure.

---

## 📄 License

MIT — see [LICENSE.md](LICENSE.md).
