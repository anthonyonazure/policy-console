#!/bin/sh
# Start Policy Console READ-ONLY, using the read-only app registration stored in
# 1Password. Nothing secret is written to disk: the credential is read when this
# starts and lives only in this process's environment.
#
# Read-only means every write (deploy, revert, modify, delete) is refused, so no
# allow-list is needed and a mistake cannot change a tenant.
# To make changes you must use the separate write registration deliberately; that
# is intentionally not scripted here.
set -eu
cd "$(dirname "$0")/.."
ITEM=xmwqbb3nfywejo2bbmi2u6am7a
export PC_CLIENT_ID="$(opq read "op://Personal/$ITEM/appId")"
export PC_CLIENT_SECRET="$(opq read "op://Personal/$ITEM/credential")"
export PC_READ_ONLY=true
[ -x ./policyconsole ] || go build -o policyconsole ./cmd/policyconsole
exec ./policyconsole
