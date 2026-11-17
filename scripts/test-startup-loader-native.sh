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
' loader-fixture go test "${flags[@]}" -tags razvilka_native_fixture \
  -count=1 -v -timeout=90s ./internal/startuptools \
  -run '^Test(ARM64LoaderCPUID|AMD64LoaderCPUID)'
