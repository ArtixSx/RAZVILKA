#!/bin/sh
set -eu
umask 077
[ "$(uname -s)" = Linux ] || { echo "Ordinary self update checks require Linux" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "Ordinary self update checks require an isolated root runner" >&2; exit 2; }
GO="${GO:-go}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$HERE"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOFLAGS="${GOFLAGS:--p=2}"
export GOTOOLCHAIN=local
# Actual Start/Wait, held executable identity and ordinary H -> S -> C join.
# Synthetic children/private TempDir and /root fixtures only: no production
# /opt, router, listener, opkg or network. This is not genuine release acceptance.
SELECTION='^(TestNativeOrdinaryImageCommandRevocationJoinsActualChild|TestNativeOrdinaryImageCommandRejectsReplacedHeldPathBeforeStart|TestNativeOrdinaryJoinIsProducedAfterActualAllChildWait|TestOrdinaryInstallerJoinNativeActualChainAndPIDReuseRefusal)$'
LOG="$(mktemp "${TMPDIR:-/tmp}/razvilka-ordinary-native.XXXXXX")"
trap 'rm -f "$LOG"' EXIT HUP INT TERM
"$GO" test ./internal/updatecheck -list "$SELECTION" >"$LOG"
for TEST in TestNativeOrdinaryImageCommandRevocationJoinsActualChild TestNativeOrdinaryImageCommandRejectsReplacedHeldPathBeforeStart TestNativeOrdinaryJoinIsProducedAfterActualAllChildWait TestOrdinaryInstallerJoinNativeActualChainAndPIDReuseRefusal; do
  grep -Fx "$TEST" "$LOG" >/dev/null || { echo "Ordinary native test is missing: $TEST" >&2; exit 1; }
done
RESULT=0
"$GO" test -race ./internal/updatecheck -run "$SELECTION" -v -count=1 -timeout=2m >"$LOG" 2>&1 || RESULT=$?
cat "$LOG"
[ "$RESULT" -eq 0 ] || exit "$RESULT"
if grep -E '^[[:space:]]*--- SKIP:' "$LOG" >/dev/null; then
  echo "Ordinary native gate refused a skipped prerequisite" >&2
  exit 1
fi
echo "Ordinary native producer/join checks: OK (release acceptance remains separate)"
