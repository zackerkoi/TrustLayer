#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv}"
PORT="${PORT:-8080}"
DB_PATH="${DB_PATH:-$ROOT_DIR/audit.sqlite3}"
POLICY_FILE="${POLICY_FILE:-}"

choose_python() {
  local candidate
  for candidate in "$PYTHON_BIN" python3.12 python3.11 python3.10; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi
    if "$candidate" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
    then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! PYTHON_BIN="$(choose_python)"; then
  echo "error: TrustLayer needs Python 3.10+ (tried: $PYTHON_BIN, python3.12, python3.11, python3.10)" >&2
  exit 1
fi

venv_needs_rebuild=0
if [ -x "$VENV_PATH/bin/python" ]; then
  if ! "$VENV_PATH/bin/python" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
  then
    venv_needs_rebuild=1
  fi
fi

if [ "$venv_needs_rebuild" -eq 1 ]; then
  rm -rf "$VENV_PATH"
fi

if [ ! -d "$VENV_PATH" ]; then
  "$PYTHON_BIN" -m venv "$VENV_PATH"
fi

# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"

python -m pip install --upgrade pip setuptools wheel >/dev/null
python -m pip install -e "$ROOT_DIR" >/dev/null

CMD=(python -m trustlayer.main --port "$PORT" --db-path "$DB_PATH")
if [ -n "$POLICY_FILE" ]; then
  CMD+=(--policy-file "$POLICY_FILE")
fi

echo "TrustLayer deploy-local"
echo "  root:   $ROOT_DIR"
echo "  venv:   $VENV_PATH"
echo "  port:   $PORT"
echo "  db:     $DB_PATH"
if [ -n "$POLICY_FILE" ]; then
  echo "  policy: $POLICY_FILE"
fi
echo
echo "starting TrustLayer..."

exec "${CMD[@]}"
