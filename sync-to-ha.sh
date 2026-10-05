#!/bin/bash
set -e
HA_HOST="${HA_HOST:-homeassistant.local}"
HA_USER="${HA_USER:-hassio}"

echo "Syncing honeypot add-on to ${HA_USER}@${HA_HOST}:/addons/honeypot/ ..."
rsync -av --delete --rsync-path="sudo rsync" \
    --exclude __pycache__ \
    "$(dirname "$0")/honeypot/" \
    "${HA_USER}@${HA_HOST}:/addons/honeypot/"

echo ""
echo "Done. In HA: Settings → Add-ons → ⋮ → Check for updates, then rebuild Honeypot."
