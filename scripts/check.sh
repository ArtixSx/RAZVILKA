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
for script in scripts/*.sh scripts/S99razvilka build.sh; do
  sh -n "$script"
done
sh ./scripts/check-no-z2k-runtime.sh
sh ./scripts/test-candidate-isolation.sh
sh ./scripts/test-bootstrap.sh
sh ./scripts/test-uninstall-entware.sh
if command -v node >/dev/null 2>&1; then
  node scripts/build-interface.mjs --check
  node scripts/test-interface-model.mjs
  node scripts/test-interface-contract.mjs
  node scripts/test-interface-home.mjs
  node scripts/test-component-cards-ui.mjs
  node --check cmd/razvilka/web/project-log.js
  node scripts/test-project-log-ui.mjs
  node --check cmd/razvilka/web/theme.js
  node scripts/test-theme.mjs
  node scripts/test-console-autonomy-auth.mjs
  node scripts/test-auth-resume-ui.mjs
  node --check cmd/razvilka/web/dns-service-lab.js
  node scripts/test-dns-service-lab.mjs
  node --check cmd/razvilka/web/awg-workspace.js
  node scripts/test-awg-workspace.mjs
  node --check cmd/razvilka/web/workflow-actions.js
  node --check cmd/razvilka/web/interface.js
  node --check cmd/razvilka/web/interface-model.js
  node --check cmd/razvilka/web/console.js
  node --check cmd/razvilka/web/console-autonomy.js
  node --check cmd/razvilka/web/autonomy-ui.js
  node scripts/test-autonomy-ui.mjs
  node --check cmd/razvilka/web/app.js
  node --check cmd/razvilka/web/node-browser.js
  node --check cmd/razvilka/web/node-intent-ui.js
  node --check cmd/razvilka/web/node-service-ui.js
  node --check cmd/razvilka/web/node-policy-ui.js
  node --check cmd/razvilka/web/node-activity-ui.js
  node --check cmd/razvilka/web/workspace-controls.js
  node --check cmd/razvilka/web/service-dashboard-ui.js
  node --check cmd/razvilka/web/app-update-ui.js
  node --check cmd/razvilka/web/cloudflare-accounts.js
  node --check cmd/razvilka/web/cloudflare-backups.js
  node --check cmd/razvilka/web/cloudflare-migration.js
  node scripts/test-probe-ui.mjs
  node scripts/test-cloudflare-ui.mjs
  node scripts/test-cloudflare-backup-ui.mjs
  node scripts/test-cloudflare-migration-ui.mjs
  node scripts/test-private-backup-ui.mjs
  node scripts/test-devices-persistence-ui.mjs
  node scripts/test-usque-dns-ui.mjs
  node scripts/test-provider-import-ui.mjs
  node scripts/test-node-route-ui.mjs
  node scripts/test-node-browser-ui.mjs
  node scripts/test-node-bulk-ui.mjs
  node --check cmd/razvilka/web/setup-workflows.js
  node scripts/test-setup-repair.mjs
  node scripts/test-node-intent-ui.mjs
  node scripts/test-node-service-ui.mjs
  node scripts/test-node-policy-ui.mjs
  node scripts/test-app-update-ui.mjs
  node --check cmd/razvilka/web/automation-setup.js
  node scripts/test-maintenance-ui.mjs
  node --check cmd/razvilka/web/extension-lab.js
  node scripts/test-extension-lab.mjs
  node scripts/test-workspace-controls-ui.mjs
  node scripts/test-service-dashboard-ui.mjs
  node scripts/test-engine-intent-ui.mjs
  node scripts/test-node-activity-ui.mjs
  node scripts/test-panel-loading-ui.mjs
  node scripts/test-warp-generation-ui.mjs
  node scripts/test-restore-busy-supervision.mjs
  node scripts/test-native-enrollment-supervision.mjs
fi
./build.sh
sha256sum -c dist/SHA256SUMS
sh ./scripts/test-entware-transaction.sh
echo "RAZVILKA checks: OK"
