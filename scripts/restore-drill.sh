#!/usr/bin/env bash
# Restore drill: back up the live database, restore the backup into a temp
# directory, and confirm every table has the same row count as the source.
# Usage: scripts/restore-drill.sh /path/to/policy-console.db
set -euo pipefail
SRC="${1:-${PC_DATABASE:-policy-console.db}}"
[ -f "$SRC" ] || { echo "no database at $SRC" >&2; exit 1; }
BIN="$(mktemp -d)/policyconsole"
go build -o "$BIN" ./cmd/policyconsole
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" "$(dirname "$BIN")"' EXIT

BACKUP="$(PC_DATABASE="$SRC" PC_BACKUP_DIR="$WORK/backups" "$BIN" backup)"
mkdir "$WORK/restore"
cp "$BACKUP" "$WORK/restore/policy-console.db"

"$BIN" counts "$SRC" > "$WORK/source.counts"
"$BIN" counts "$WORK/restore/policy-console.db" > "$WORK/restored.counts"

if diff -u "$WORK/source.counts" "$WORK/restored.counts"; then
  echo "RESTORE DRILL PASSED"
  cat "$WORK/restored.counts"
else
  echo "RESTORE DRILL FAILED: row counts differ" >&2
  exit 1
fi
