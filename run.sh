#!/usr/bin/env bash
set -euo pipefail

cmd=${1:-help}

function help_msg() {
  echo "Usage: $0 {build|run|run-viewer|run-dev|run-viewer-dev|help} [options]"
  echo
  echo "Commands:" 
  echo "  build            Build the docker image"
  echo "  run --mount PATH Run container and mount PATH to /data (default port 5000)"
  echo "  run-viewer       Run standalone bundle viewer in Docker (port 5001)"
  echo "  run-dev          Run locally (requires python and dependencies installed)"
  echo "  run-viewer-dev   Run bundle viewer locally on port 5001"
}

if [ "$cmd" = "build" ]; then
  docker build -t lrmetrics:latest .
  exit 0
fi

if [ "$cmd" = "run" ]; then
  shift || true
  # parse --mount
  MOUNT="$(pwd)/lrmetrics_data"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mount)
        MOUNT="$2"; shift 2;;
      *) echo "Unknown option $1"; exit 1;;
    esac
  done
  mkdir -p "$MOUNT"
  docker run --rm -p 5000:5000 -v "$MOUNT":/data lrmetrics:latest
  exit 0
fi

if [ "$cmd" = "run-viewer" ]; then
  # Standalone viewer mode: no persistent mount required.
  docker run --rm -p 5001:5001 lrmetrics:latest \
    gunicorn --bind 0.0.0.0:5001 viewer_app:app --workers 1 --timeout 180
  exit 0
fi

if [ "$cmd" = "run-dev" ]; then
  VENV_DIR="${VENV_DIR:-.venv}"
  # Recreate venv if missing or broken (e.g., after moving directories)
  if [ ! -x "$VENV_DIR/bin/python" ] || ! "$VENV_DIR/bin/python" -c 'print("ok")' >/dev/null 2>&1; then
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  . "$VENV_DIR/bin/activate"
  # Install dependencies quietly; suppress noise
  python -m pip install -r requirements.txt --quiet --disable-pip-version-check || true
  export DATA_DIR="$(pwd)/lrmetrics_data"
  mkdir -p "$DATA_DIR"
  export FLASK_APP=app.py
  python -m flask run --host=0.0.0.0
  exit 0
fi

if [ "$cmd" = "run-viewer-dev" ]; then
  VENV_DIR="${VENV_DIR:-.venv}"
  if [ ! -x "$VENV_DIR/bin/python" ] || ! "$VENV_DIR/bin/python" -c 'print("ok")' >/dev/null 2>&1; then
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  . "$VENV_DIR/bin/activate"
  python -m pip install -r requirements.txt --quiet --disable-pip-version-check || true
  export FLASK_APP=viewer_app.py
  python -m flask run --host=0.0.0.0 --port 5001
  exit 0
fi

help_msg
