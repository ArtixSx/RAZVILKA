#!/bin/sh
# Explicit coordinator-only fixture; no service/iptables/NFQUEUE mutation.
set -eu
: "${RAZVILKA_NFQWS_NATIVE_BINARY:?absolute path to genuine reviewed nfqws2 required}"
: "${RAZVILKA_NFQWS_NATIVE_ASSETS:?reviewed disposable flat Lua/blob fixture directory required}"
case "$RAZVILKA_NFQWS_NATIVE_BINARY" in /*) ;; *) exit 2 ;; esac
case "$RAZVILKA_NFQWS_NATIVE_ASSETS" in /*) ;; *) exit 2 ;; esac
test -x "$RAZVILKA_NFQWS_NATIVE_BINARY"
for file in zapret-lib.lua zapret-antidpi.lua zapret-auto.lua tls_clienthello.bin; do
    test -r "$RAZVILKA_NFQWS_NATIVE_ASSETS/$file"
done
export GOTOOLCHAIN=local
export GOMAXPROCS=2
export GOFLAGS=-p=2
exec "${GO_BIN:-go}" test -count=1 -v -timeout=2m ./internal/strategylab -run '^TestNFQWSNativeCompatibilityNoIntercept$'
