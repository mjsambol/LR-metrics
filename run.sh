#!/usr/bin/env bash
set -euo pipefail

cmd=${1:-help}

function help_msg() {
  echo "Usage: $0 {build|run|run-dev|help} [options]"
  echo
  echo "Commands:" 
  echo "  build            Build the docker image"
  echo "  run --mount PATH Run container and mount PATH to /data (default port 5000)"
  echo "  run-dev          Run locally (requires python and dependencies installed)"
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

help_msg
