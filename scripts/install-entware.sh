#!/bin/sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec sh "$HERE/upgrade-entware.sh" --apply "$@"
