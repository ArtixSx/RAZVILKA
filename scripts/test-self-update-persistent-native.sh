#!/bin/sh
set -eu
umask 077
[ "$(uname -s)" = Linux ] || { echo "Persistent self update acceptance requires Linux" >&2; exit 2; }
GO="${GO:-go}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$HERE"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOFLAGS="${GOFLAGS:--p=2}"
export GOTOOLCHAIN=local
# Root owns native execution. This runs the existing matching Action consumer
# with private relocated command fixtures, not production /opt/main live LKG.
"$GO" test -race ./internal/updatecheck \
  -run '^TestNativeSelfUpdatePersistentCrashRecovery$' -v -count=1 -timeout=14m
