#!/usr/bin/env bash
# Add Scrim's recommended deny rules to a project's .claude/settings.json.
#
# Why: Scrim relies on the agent being routed through safe_read/safe_grep/
# safe_shell rather than the native Read/Bash on sensitive paths. The most
# reliable way to enforce that is a deny rule on the native tools, which this
# script installs.
#
# This script:
#   1. Reads ./.claude/settings.json (creating it if absent).
#   2. Diffs against the recommended deny rules.
#   3. Prints the additions and prompts before writing.
#   4. Preserves every existing key — only appends missing rules.
#
# Idempotent. Safe to re-run.

set -euo pipefail

# Keep in sync with REQUIRED_DENY_RULES in src/mcp/tools.ts.
REQUIRED=(
  "Read(./.env*)"
  "Read(**/*.pem)"
  "Read(**/secrets/**)"
  "Bash(env)"
  "Bash(printenv*)"
  "Bash(*kubectl get secret*)"
)

PROJECT_ROOT="${1:-$PWD}"
SETTINGS_DIR="${PROJECT_ROOT}/.claude"
SETTINGS_FILE="${SETTINGS_DIR}/settings.json"

if ! command -v node >/dev/null 2>&1; then
  echo "scrim: node is required to safely merge JSON" >&2
  exit 1
fi

mkdir -p "$SETTINGS_DIR"
if [ ! -f "$SETTINGS_FILE" ]; then
  echo "{}" > "$SETTINGS_FILE"
fi

# Compute the additions via Node so we don't have to parse JSON in bash.
ADDITIONS_JSON=$(
  REQUIRED_RULES="$(printf '%s\n' "${REQUIRED[@]}")" \
  SETTINGS_FILE="$SETTINGS_FILE" \
  node <<'EOF'
const fs = require('node:fs');
const required = process.env.REQUIRED_RULES.split('\n').filter(Boolean);
const path = process.env.SETTINGS_FILE;
let cfg;
try {
  cfg = JSON.parse(fs.readFileSync(path, 'utf8'));
} catch (err) {
  console.error('scrim: failed to parse', path, '-', err.message);
  process.exit(1);
}
const current = (cfg.permissions && Array.isArray(cfg.permissions.deny))
  ? cfg.permissions.deny.filter((x) => typeof x === 'string')
  : [];
const missing = required.filter((r) => !current.includes(r));
process.stdout.write(JSON.stringify(missing));
EOF
)

MISSING_COUNT=$(node -e "process.stdout.write(String(JSON.parse(process.argv[1]).length))" -- "$ADDITIONS_JSON")

if [ "$MISSING_COUNT" = "0" ]; then
  echo "scrim: all ${#REQUIRED[@]} deny rules already present in $SETTINGS_FILE — nothing to do."
  exit 0
fi

echo "scrim: $MISSING_COUNT deny rule(s) missing from $SETTINGS_FILE:"
echo "$ADDITIONS_JSON" | node -e '
  const items = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
  for (const i of items) console.log("  +", i);
'

# Allow a non-interactive run for CI / scripts:
#   ./scripts/install-deny-rules.sh -y
APPLY="${APPLY:-}"
if [ "${2:-}" = "-y" ] || [ "${1:-}" = "-y" ]; then APPLY="y"; fi

if [ -z "$APPLY" ]; then
  printf "Add these rules to %s? [y/N] " "$SETTINGS_FILE"
  read -r APPLY
fi

case "$APPLY" in
  y|Y|yes|YES)
    ADDITIONS_JSON="$ADDITIONS_JSON" \
    SETTINGS_FILE="$SETTINGS_FILE" \
    node <<'EOF'
const fs = require('node:fs');
const path = process.env.SETTINGS_FILE;
const additions = JSON.parse(process.env.ADDITIONS_JSON);
const cfg = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!cfg.permissions || typeof cfg.permissions !== 'object') cfg.permissions = {};
const deny = Array.isArray(cfg.permissions.deny) ? cfg.permissions.deny : [];
const merged = [...deny];
for (const rule of additions) {
  if (!merged.includes(rule)) merged.push(rule);
}
cfg.permissions.deny = merged;
fs.writeFileSync(path, JSON.stringify(cfg, null, 2) + '\n');
console.log('scrim: wrote', merged.length, 'deny rule(s) to', path);
EOF
    echo "scrim: done. Run /scrim:doctor in Claude Code to verify."
    ;;
  *)
    echo "scrim: aborted. No changes made."
    exit 1
    ;;
esac
