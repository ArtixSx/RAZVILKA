#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
gofmt -w cmd internal
go test ./...
go vet ./...
sh -n scripts/*.sh build.sh
if command -v node >/dev/null 2>&1; then node --check cmd/razvilka/web/app.js; fi
./build.sh
sha256sum -c dist/SHA256SUMS
echo "RAZVILKA checks: OK"
