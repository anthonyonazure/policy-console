#!/bin/sh
# Start Policy Console on this Mac with Planner posting switched on, then open it.
#
# Local only: it listens on 127.0.0.1, so only this Mac can reach it, and sign-in is
# switched off because of that. The Planner secret is read from the Mac Keychain when
# this starts and lives only in this process's environment. (Interim: move it to
# 1Password and change the one `security` line below when `opq` answers again.)
#
# The tenant, app and group identifiers come from a local settings file, not this repo.
#
# Planner writes only create and edit tasks in the IT Support group. No client tenant
# is touched: no write app for any client is configured here.
set -eu
cd "$(dirname "$0")/.."

ADDR="127.0.0.1:4930"
export PC_ADDR="$ADDR"
export PC_AUTH_DISABLED=true
SETTINGS="${PC_PLANNER_ENV:-$HOME/.config/policy-console/planner.env}"
[ -r "$SETTINGS" ] || { echo "Missing $SETTINGS (needs PC_TENANT_ID, PC_PLANNER_CLIENT_ID, PC_PLANNER_GROUP_ID)"; exit 1; }
set -a
. "$SETTINGS"
set +a
PC_PLANNER_CLIENT_SECRET="$(security find-generic-password -s policy-console-planner-secret -a policy-console-planner -w)"
export PC_PLANNER_CLIENT_SECRET

if lsof -nP -iTCP:4930 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Something is already running on $ADDR. Opening it."
  open "http://$ADDR"
  exit 0
fi

go build -o policyconsole ./cmd/policyconsole
(sleep 2; open "http://$ADDR") &
exec ./policyconsole
