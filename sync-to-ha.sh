#!/bin/bash
set -e
HA_HOST="${HA_HOST:-homeassistant.local}"
HA_USER="${HA_USER:-hassio}"

echo "Syncing honeypot add-on to ${HA_USER}@${HA_HOST}:/addons/honeypot/ ..."
# Stage a copy without the "image" key, so HA builds this local copy instead of
# pulling the published image.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
rsync -a --exclude __pycache__ "$(dirname "$0")/honeypot/" "$STAGE/"
python3 -c "import json,sys; p=sys.argv[1]; c=json.load(open(p)); c.pop('image', None); json.dump(c, open(p,'w'), indent=2)" "$STAGE/config.json"

rsync -av --delete --rsync-path="sudo rsync" "$STAGE/" "${HA_USER}@${HA_HOST}:/addons/honeypot/"

echo ""
echo "Done. In HA: Settings → Add-ons → ⋮ → Check for updates, then rebuild Honeypot."
