#!/bin/bash
set -e

# Options are read from /data/options.json (add-on) or env vars (standalone)
# by config.py, so there is nothing to export here.
export DATA_DIR="${DATA_DIR:-/data}"
export PYTHONUNBUFFERED=1

exec python /app/main.py
