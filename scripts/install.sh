#!/usr/bin/env bash
# Manual install path for users who aren't using /plugin install.
# Builds the TypeScript sources to bin/ and prints next steps.
# Does NOT modify ~/.claude.json or any global config.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v node >/dev/null 2>&1; then
  echo "scrim: node 20+ is required" >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "scrim: installing dependencies..."
  npm install
fi

echo "scrim: building..."
npm run build

cat <<EOF

scrim is built at: $ROOT

To load it in Claude Code:
  claude --plugin-dir "$ROOT"

Or, to install via marketplace once published:
  /plugin install scrim@<marketplace>

Configure detection in your repo by creating .scrim/policy.yml
(see policy/default-policy.yml for the schema).
EOF
