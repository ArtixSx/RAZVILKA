#!/bin/sh
set -eu
# Independent test process and namespaces; never reuse the positive case's CA
# cache, native owners or profile artifact as failure evidence.
export RAZVILKA_MIHOMO_LIVE_TEST_CASE=postcas-failure
unset RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT
exec sh "$(dirname -- "$0")/test-mihomo-live-native.sh"
