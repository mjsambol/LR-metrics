#!/usr/bin/env bash
set -euo pipefail

# Ensure data directory exists
DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# Recommend setting a strong FLASK_SECRET in production
if [ -z "${FLASK_SECRET:-}" ]; then
  cat >&2 <<'EOF'
WARNING: FLASK_SECRET is not set. Using the default development secret.
Set FLASK_SECRET to a strong random value in production to secure sessions.
EOF
fi

# Retrieval can legitimately take longer than Gunicorn's default worker timeout.
# Apply a safer default unless a timeout is already configured explicitly.
if [ "${1:-}" = "gunicorn" ]; then
  if [[ " $* " != *" --timeout "* ]] && [[ " ${GUNICORN_CMD_ARGS:-} " != *" --timeout "* ]]; then
    export GUNICORN_CMD_ARGS="${GUNICORN_CMD_ARGS:-} --timeout ${GUNICORN_TIMEOUT:-180}"
  fi
fi

# Exec the passed command (e.g. gunicorn)
exec "$@"
