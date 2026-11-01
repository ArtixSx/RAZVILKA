#!/bin/sh
set -eu
# The common pinned-artifact/ELF/namespace producer remains authoritative.
# This selects only the fixed tagged LAN cases, never supplied commands or
# host namespaces. Every case gets the same fresh private mount+network setup.
export RAZVILKA_MANAGED_PROBE_LAN_NATIVE=1
exec sh "$(dirname "$0")/test-managed-probe-native.sh"
