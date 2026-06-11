---
description: Route file reads and shell commands through Scrim's safe_read, safe_grep, and safe_shell tools whenever the target may contain secrets or PII (config files, .env*, *.pem, secrets/**, env-dumping commands, kubectl get secret, docker inspect, git remote -v with tokens, connection strings). Scrim returns tokenized content; the PreToolUse hook on Write|Edit|MultiEdit restores real values before bytes hit disk, so the model never sees raw secrets but files stay correct.
---

# Using Scrim

Scrim is a context firewall. Sensitive content is replaced with stable tokens of the form `⟦scrim:<class>:<id>⟧` before it ever enters your context. You can reason about and edit that content normally — when you write a file back, Scrim's PreToolUse hook de-tokenizes the tokens to the real values on disk.

## When to use Scrim tools

Prefer Scrim's tools over native `Read` and `Bash` whenever the target could contain credentials or personal data:

- **`safe_read`** — for any config-like file: `.env*`, `*.tfvars`, `*.pem`, `config.{json,yml,yaml,toml}`, `settings.py`, files under `secrets/**`, seed/fixture data with personal info.
- **`safe_grep`** — for searches across paths that may include the above.
- **`safe_shell`** — for commands whose output frequently contains secrets: `env`, `printenv`, `kubectl get secret -o yaml`, `docker inspect`, `git remote -v`, anything that prints a connection string.

Use native `Read`/`Bash` for everything else (source code, build output, etc.).

## How tokens behave

A token like `⟦scrim:db_password:a1b2c3⟧` is opaque but stable within a session. Treat it as a placeholder for the original value:

- Copy it through Edits unchanged. The hook will restore it on write.
- Don't try to "decode" or guess what's behind a token — the vault is local and won't tell you.
- If a token appears in a diff or commit message you're drafting, that's fine for review, but the user can rotate the value out of band.

## When Scrim blocks

If detection errors or the vault is unavailable, Scrim is fail-closed: the tool call is rejected rather than returning raw content. Surface the error to the user, suggest checking `/scrim:status`, and don't try to bypass with native `Read`/`Bash`.

## Quick check

Run `/scrim:status` to see active rules, vault size, and recent detections at any time.
