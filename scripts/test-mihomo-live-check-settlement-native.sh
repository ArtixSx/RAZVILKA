#!/bin/sh
set -eu
# Separate original process/net/mount namespace from both lifecycle and 503.
export RAZVILKA_MIHOMO_LIVE_TEST_CASE=check-settlement
unset RAZVILKA_MIHOMO_LIVE_PROFILE_OUTPUT
exec sh "$(dirname -- "$0")/test-mihomo-live-native.sh"
