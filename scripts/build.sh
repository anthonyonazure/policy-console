#!/usr/bin/env bash
# Builds the console for every platform it needs to run on.
# One file per platform, no runtime dependencies, templates included.
set -euo pipefail
cd "$(dirname "$0")/.."
out="dist"
mkdir -p "$out"
version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

go test ./...

build() {
  local goos="$1" goarch="$2" ext="${3:-}"
  echo "building $goos/$goarch"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$version" \
    -o "$out/policyconsole-$goos-$goarch$ext" ./cmd/policyconsole
}

build darwin arm64
build darwin amd64
build windows amd64 .exe
build linux amd64
build linux arm64
ls -lh "$out"
