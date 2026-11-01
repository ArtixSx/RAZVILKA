#!/bin/sh
set -eu
export RAZVILKA_MIHOMO_MAIN_NATIVE_BINDING=1
exec sh "$(dirname -- "$0")/test-mihomo-main-native.sh"
