#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.postgres.yml}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-55432}"
PG_DB="${PG_DB:-trustlayer}"
PG_USER="${PG_USER:-trustlayer}"
PG_PASSWORD="${PG_PASSWORD:-trustlayer}"
TEST_DSN="${TRUSTLAYER_TEST_POSTGRES_DSN:-postgresql://${PG_USER}:${PG_PASSWORD}@${PG_HOST}:${PG_PORT}/${PG_DB}}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv}"

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

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: docker daemon is not running or not reachable" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose -f "$COMPOSE_FILE")
else
  echo "error: docker compose is required" >&2
  exit 1
fi

if ! PYTHON_BIN="$(choose_python)"; then
  echo "error: TrustLayer needs Python 3.10+" >&2
  exit 1
fi

if [ ! -d "$VENV_PATH" ]; then
  "$PYTHON_BIN" -m venv "$VENV_PATH"
fi

# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"

python -m pip install --upgrade pip setuptools wheel >/dev/null
python -m pip install -e "$ROOT_DIR[postgres]" >/dev/null

cleanup() {
  "${COMPOSE_CMD[@]}" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${COMPOSE_CMD[@]}" up -d >/dev/null

for _ in $(seq 1 30); do
  if python - <<PY >/dev/null 2>&1
import socket
s = socket.create_connection(("${PG_HOST}", ${PG_PORT}), timeout=1)
s.close()
PY
  then
    break
  fi
  sleep 1
done

echo "TrustLayer PostgreSQL control plane test"
echo "  compose: $COMPOSE_FILE"
echo "  dsn:     $TEST_DSN"
echo

TRUSTLAYER_TEST_POSTGRES_DSN="$TEST_DSN" \
PYTHONPATH=src python -m unittest tests.test_control_plane.ControlPlanePostgresIntegrationTest -v
