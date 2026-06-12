#!/usr/bin/env bash
# Install Microsoft Presidio as Scrim's optional PII sidecar.
#
# Creates a project-local Python venv under .scrim/presidio-venv/, pins
# presidio-analyzer and its NER model, and writes a `scrim-presidio` shim
# the detection engine talks to over stdin/stdout JSON.
#
# Idempotent: re-running upgrades nothing, only fills gaps. To start over
# delete .scrim/presidio-venv/ first.
#
# Opt-in: nothing in Scrim's default policy uses Presidio. After install,
# enable it explicitly:
#   .scrim/policy.yml
#     detection:
#       presidio: true
# and either add `.scrim/presidio-venv/bin` to PATH, or set
#   detection:
#     presidio_command: /abs/path/to/.scrim/presidio-venv/bin/scrim-presidio

set -euo pipefail

# Pin the analyzer version that has shipped stable JSON output for the
# entities Scrim's bridge expects (PERSON / LOCATION / EMAIL_ADDRESS /
# PHONE_NUMBER / US_SSN / CREDIT_CARD / IP_ADDRESS / URL). Bump deliberately
# and re-test src/engine/presidio.test.ts against the new payload shape.
PRESIDIO_VERSION="${PRESIDIO_VERSION:-2.2.355}"
SPACY_MODEL="${SPACY_MODEL:-en_core_web_sm}"

REPO_ROOT="$(pwd)"
VENV_DIR="${REPO_ROOT}/.scrim/presidio-venv"
SHIM="${VENV_DIR}/bin/scrim-presidio"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is not on PATH; install Python 3.9+ and re-run." >&2
  exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
  echo "error: presidio-analyzer requires Python 3.9+ (found ${PY_VERSION})." >&2
  exit 1
fi

mkdir -p "${REPO_ROOT}/.scrim"

if [ ! -d "${VENV_DIR}" ]; then
  echo "creating venv at ${VENV_DIR}..."
  python3 -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

python -m pip install --quiet --upgrade pip
python -m pip install --quiet "presidio-analyzer==${PRESIDIO_VERSION}"

# Presidio's default NLP engine downloads the spaCy model on first use, but
# pre-downloading it now means the first scrim-presidio invocation isn't
# multi-second slow.
python -m spacy download "${SPACY_MODEL}" >/dev/null

cat > "${SHIM}" <<'EOF'
#!/usr/bin/env bash
# scrim-presidio: stdin/stdout JSON bridge to presidio-analyzer.
# Input  (stdin):  {"text": "..."}
# Output (stdout): [{"start":N,"end":M,"entity_type":"PERSON"}, ...]
#
# Scrim consumes only the span shape; raw text NEVER leaves this process.
# Invoked with --stdin-json so future modes can be added without breaking
# the existing contract.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "${HERE}/activate"
exec python -c '
import json, sys
from presidio_analyzer import AnalyzerEngine
payload = json.load(sys.stdin)
text = payload.get("text", "")
analyzer = AnalyzerEngine()
results = analyzer.analyze(text=text, language="en")
out = [{"start": r.start, "end": r.end, "entity_type": r.entity_type} for r in results]
json.dump(out, sys.stdout)
'
EOF
chmod +x "${SHIM}"

cat <<EOF

scrim-presidio installed at: ${SHIM}
presidio-analyzer ${PRESIDIO_VERSION}
spaCy model: ${SPACY_MODEL}

next steps:
  1. enable Presidio in .scrim/policy.yml:
       detection:
         presidio: true
         presidio_command: ${SHIM}

  2. confirm with /scrim:doctor — the presidio-binary check should pass.

uninstall: rm -rf "${VENV_DIR}"
EOF
