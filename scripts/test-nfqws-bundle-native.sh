#!/bin/sh
# Coordinator-only Linux file/provider verification. No opkg, runtime, hooks,
# network, service or listener. Optional official IPK must already be local.
set -eu
case "$(uname -s)" in Linux) ;; *) echo 'SKIP managed NFQWS native: requires Linux'; exit 0 ;; esac
if [ "$(id -u)" != 0 ]; then
  echo 'FAIL managed NFQWS native: root-euid required for actual foreign-owner refusal fixtures' >&2
  exit 1
fi
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"
GO="${GO:-go}"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
GOMAXPROCS="${GOMAXPROCS:-2}"
GOFLAGS="${GOFLAGS:--p=2}"
export GOTOOLCHAIN GOMAXPROCS GOFLAGS
"$GO" test -race ./internal/components -run 'ManagedNFQWS' -count=1 -timeout=3m
