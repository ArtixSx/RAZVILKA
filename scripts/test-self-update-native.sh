#!/bin/sh
set -eu
umask 077
[ "$(uname -s)" = Linux ] || { echo "Native self update checks require Linux" >&2; exit 2; }
GO="${GO:-go}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$HERE"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOFLAGS="${GOFLAGS:--p=2}"
export GOTOOLCHAIN=local
"$GO" version
# No root, router, opkg, account, DNS, listener or network fixture is used.
# Command children and all journals/images live exclusively in Go TempDir.
"$GO" test -race ./internal/updatecheck ./internal/selfupdatejournal ./internal/operationgate \
  -run 'NativeSelfUpdate|FileJournal|PrivateDirectory|FileCommandLease|FileCommandReceipt|StopBeforeFiles|AtomicFileEffect|TerminalArtifacts|TerminalFileInspection|PrivateSnapshotExcludes|FileEffectAdmission|FileStopConsumer|FileReview' \
  -count=1 -timeout=3m
