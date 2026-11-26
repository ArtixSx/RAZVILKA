#!/bin/sh
# Coordinator-only fixed Go subreaper fixtures; no genuine CLI/Lua claim.
set -eu
test "$(uname -s)" = Linux
test "${RAZVILKA_NFQWS_PROCESS_FIXTURE:-}" = 1
export GOTOOLCHAIN=local
export GOMAXPROCS=2
export GOFLAGS=-p=2
exec "${GO_BIN:-go}" test -count=1 -v -timeout=2m ./internal/components -run '^TestNFQWSSupervisionKernelReceipts$'
