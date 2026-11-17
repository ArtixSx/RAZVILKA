#!/usr/bin/env bash
# Synthetic loader bytes are never executed. Only a disposable mount namespace
# receives the /opt tmpfs; the host's files, ownership and modes remain intact.
set -euo pipefail
mode=${1:-normal}
if (( $# > 1 )) || [[ "$mode" != normal && "$mode" != race ]]; then
  echo 'usage: test-startup-loader-native.sh [normal|race]' >&2
  exit 2
fi
if [[ $(id -u) != 0 ]]; then
  echo 'root is required for the private loader fixture' >&2
  exit 1
fi
flags=()
if [[ "$mode" == race ]]; then flags=(-race); fi
# setup-go may live under /opt/hostedtoolcache, which the fixture must hide.
# Compile before entering the namespace; the test executable needs no compiler.
trial=$(mktemp -d /root/razvilka-loader-native.XXXXXX)
cleanup_trial() {
  status=$?
  trap - EXIT
  if ! rm -f -- "$trial/startup.test"; then status=1; fi
  if ! rmdir -- "$trial"; then status=1; fi
  exit "$status"
}
trap cleanup_trial EXIT
go test "${flags[@]}" -tags razvilka_native_fixture -c \
  -o "$trial/startup.test" ./internal/startuptools
unshare --mount --propagation private bash -euo pipefail -c '
  test -d /opt && test ! -L /opt
  mount -t tmpfs -o mode=0755,size=8m,nosuid,nodev,noexec tmpfs /opt
  cleanup() {
    status=$?
    trap - EXIT
    if ! umount /opt; then status=1; fi
    exit "$status"
  }
  trap cleanup EXIT
  "$@"
' loader-fixture "$trial/startup.test" -test.count=1 -test.v -test.timeout=90s \
  -test.run '^Test(ARM64LoaderCPUID|AMD64LoaderCPUID)'
