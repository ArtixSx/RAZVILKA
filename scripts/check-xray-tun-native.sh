#!/bin/sh
# Coordinator-only designated Linux VM. Fixture namespaces are isolated, and
# only names created by the test are removed. Production needs no namespaces.
set -eu
: "${RAZVILKA_XRAY_NATIVE:?Set pinned absolute Xray path}"
: "${RAZVILKA_SINGBOX_NATIVE:?Set pinned absolute Sing-box path with_gvisor}"
GO=${GO:-go}
for binary in "$RAZVILKA_XRAY_NATIVE" "$RAZVILKA_SINGBOX_NATIVE"; do
  case "$binary" in /*) ;; *) echo 'Native binary paths must be absolute' >&2; exit 2;; esac
  [ -x "$binary" ] || { echo 'Native binary is not executable' >&2; exit 2; }
  "$binary" version
done
"$GO" version
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
"$GO" test -c -o "$tmp/xray-tun-native.test" ./internal/dataplane
export RAZVILKA_XRAY_TUN_NATIVE=1
exec_test="$tmp/xray-tun-native.test"
RAZVILKA_XRAY_COMMIT_TRANSIT_NATIVE= "$exec_test" -test.run '^TestNativeScopedXrayTUN$' -test.v -test.timeout 4m
for scenario in success commit-refusal; do
  log="$tmp/commit-$scenario.log"
  if ! RAZVILKA_XRAY_COMMIT_TRANSIT_NATIVE="$scenario" "$exec_test" \
      -test.run '^TestNativeScopedXrayTUN$' -test.v -test.timeout 4m > "$log" 2>&1; then
    cat "$log"
    exit 1
  fi
  cat "$log"
  test "$(grep -Fc "Xray commit transit $scenario: PASS" "$log")" -eq 1
done
