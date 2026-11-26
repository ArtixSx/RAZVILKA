#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
test "$#" = 3 || { echo "Usage: sh build-relay.sh SOURCE_ARCHIVE NEW_BUILD_DIRECTORY PATCH" >&2; exit 2; }
case "$1" in /*) archive=$1;; *) exit 2;; esac
case "$2" in /*) build=$2;; *) exit 2;; esac
case "$3" in /*) patchfile=$3;; *) exit 2;; esac
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
printf '%s  %s\n' a7b86050091c5a268d81de70b95d3bb0871ba4136160662b6496596761c2f9a7 "$archive" | sha256sum -c -
umask 077
mkdir "$build"
tar -xJf "$archive" -C "$build"
src="$build/hev-socks5-tunnel-2.17.1"
cd "$src"
printf '%s  %s\n' 30dcee28f54a82305dd2da9b0b640a0dc54550d865bc2cf86cdafb404b7e7984 "$patchfile" | sha256sum -c -
patch -p1 <"$patchfile"
detector=third-part/hev-task-system/src/lib/misc/hev-task-stack-detector.c
printf '%s  %s\n' 500bd669dbeb6e125ff21c48877f42d80b378a7c3f09b2d12bee0d784a702733 "$detector" | sha256sum -c -
make -j2 static
cc -O2 -Wall -Wextra -Werror -I"$src/src" "$base/relay.c" \
    "$src/bin/libhev-socks5-tunnel.a" "$src/third-part/yaml/bin/libyaml.a" \
    "$src/third-part/lwip/bin/liblwip.a" "$src/third-part/hev-task-system/bin/libhev-task-system.a" \
    -lpthread -o "$build/relay"

if [ "${RAZVILKA_BUILD_NFQUEUE:-0}" = 1 ]; then
    cc -O2 -Wall -Wextra -Werror "$base/queue-source.c" -lmnl -lnetfilter_queue -o "$build/queue-source"
fi
