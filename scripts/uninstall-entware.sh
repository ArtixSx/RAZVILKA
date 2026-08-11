#!/bin/sh
set -eu
[ -x /opt/etc/init.d/S99razvilka ] && /opt/etc/init.d/S99razvilka stop || true
rm -f /opt/etc/init.d/S99razvilka /opt/bin/razvilka
# Keep config/catalog/cache by default: future reinstall or rollback can reuse them.
echo "RAZVILKA binary/service removed. Data kept at /opt/etc/razvilka and /opt/var/cache/razvilka"
