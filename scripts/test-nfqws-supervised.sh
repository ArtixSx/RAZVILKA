#!/bin/sh
# Coordinator-only genuine CLI/Lua or fixed Go kernel/controller fixtures.
# The helper is compiled into an explicitly prepared private directory.
set -eu
test "$(uname -s)" = Linux
: "${RAZVILKA_NFQWS_FIXTURE_WORKDIR:?absolute private owned fixture directory required}"
case "$RAZVILKA_NFQWS_FIXTURE_WORKDIR" in /*) ;; *) exit 2 ;; esac
test -d "$RAZVILKA_NFQWS_FIXTURE_WORKDIR"
: "${RAZVILKA_NFQWS_SUPERVISED_FIXTURE:?select genuine or controller}"
case "$RAZVILKA_NFQWS_SUPERVISED_FIXTURE" in
    genuine)
        : "${RAZVILKA_NFQWS_NATIVE_REVIEW:?absolute owner-reviewed manifest JSON required}"
        : "${RAZVILKA_NFQWS_NATIVE_SUPERVISED_CASE:?select normal or lua-reject}"
        case "$RAZVILKA_NFQWS_NATIVE_SUPERVISED_CASE" in normal|lua-reject) ;; *) exit 2 ;; esac
        run='^TestNFQWSNativeSupervisedCompatibility$'
        ;;
    controller)
        test "${RAZVILKA_NFQWS_PROCESS_FIXTURE:-}" = 1
        run='^TestNFQWSSupervisedController'
        ;;
    *) exit 2 ;;
esac
export GOTOOLCHAIN=local
export GOMAXPROCS=2
export GOFLAGS=-p=2
umask 077
"${GO_BIN:-go}" test -c -o "$RAZVILKA_NFQWS_FIXTURE_WORKDIR/strategylab-supervised.test" ./internal/strategylab
exec "$RAZVILKA_NFQWS_FIXTURE_WORKDIR/strategylab-supervised.test" -test.v -test.timeout=2m -test.run="$run"
