#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
unformatted="$(gofmt -l cmd internal)"
if [ -n "$unformatted" ]; then
  echo "gofmt is required for:"
  echo "$unformatted"
  exit 1
fi
go test ./...
go test -race ./...
go vet ./...
sh -n scripts/*.sh build.sh
if command -v node >/dev/null 2>&1; then
  node --check cmd/razvilka/web/app.js
  node --check cmd/razvilka/web/cloudflare-accounts.js
  node --check cmd/razvilka/web/cloudflare-backups.js
  node --check cmd/razvilka/web/cloudflare-migration.js
  node scripts/test-probe-ui.mjs
  node scripts/test-cloudflare-ui.mjs
  node scripts/test-cloudflare-backup-ui.mjs
  node scripts/test-cloudflare-migration-ui.mjs
fi
./build.sh
sha256sum -c dist/SHA256SUMS
sh ./scripts/test-entware-transaction.sh
echo "RAZVILKA checks: OK"
