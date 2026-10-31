#!/usr/bin/env bash
# Copies the policy template JSON from the OneDrive folder that is the source of
# truth into this repo, where it gets compiled into the binary.
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:?usage: sync-templates.sh <folder holding the master policy templates>}"
[ -d "$src" ] || { echo "template folder not found: $src" >&2; exit 1; }

for category in conditional-access defender intune; do
  dest="internal/catalog/files/$category"
  mkdir -p "$dest"
  cp -R "$src/$category/json/." "$dest/"
done

# A client name or group id reaching a shared template is the failure this guards against.
if grep -rIl --include='*.json' -E '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b' internal/catalog/files >/dev/null 2>&1; then
  echo "WARNING: a raw GUID appears in a template. Check it is a Microsoft built-in id, not a client object id:"
  grep -rIn --include='*.json' -E '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b' internal/catalog/files | head -20
fi

go test ./internal/catalog/
echo "templates synced: $(find internal/catalog/files -name '*.json' | wc -l | tr -d ' ') files"
