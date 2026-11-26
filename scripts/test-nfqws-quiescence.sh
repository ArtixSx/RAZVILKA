#!/bin/sh
# Coordinator-only fixed Go process fixtures: timer and inherited pipes.
# No Lua, NFQUEUE, firewall or network. PASS never grants tree quiescence.
set -eu
: "${RAZVILKA_NFQWS_PROCESS_FIXTURE:?explicit coordinator opt-in required}"
test "$RAZVILKA_NFQWS_PROCESS_FIXTURE" = 1
test "$(uname -s)" = Linux
export GOTOOLCHAIN=local
export GOMAXPROCS=2
export GOFLAGS=-p=2
exec "${GO_BIN:-go}" test -count=1 -v -timeout=2m ./internal/strategylab -run '^TestNFQWSNativeCompatibility(ProcessCancellation|InheritedPipes)$'
