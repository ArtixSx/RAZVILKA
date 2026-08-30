#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT"
mkdir -p dist
VERSION_FILE="$ROOT/VERSION"
[ -f "$VERSION_FILE" ] || { echo "Missing canonical VERSION file: $VERSION_FILE" >&2; exit 1; }
PROJECT_VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
case "$PROJECT_VERSION" in
  ''|*[!0-9A-Za-z.+-]*) echo "Invalid canonical version: $PROJECT_VERSION" >&2; exit 1 ;;
esac
VERSION="${RAZVILKA_VERSION:-$PROJECT_VERSION}"
COMMIT="${RAZVILKA_COMMIT:-unknown}"
BUILD_TIME="${RAZVILKA_BUILD_TIME:-unknown}"
DIRTY="${RAZVILKA_DIRTY:-unknown}"
LDFLAGS="-s -w -X github.com/ArtixSx/razvilka/internal/app.Version=$VERSION -X github.com/ArtixSx/razvilka/internal/app.BuildCommit=$COMMIT -X github.com/ArtixSx/razvilka/internal/app.BuildTime=$BUILD_TIME -X github.com/ArtixSx/razvilka/internal/app.BuildDirty=$DIRTY"
build(){
  if [ -n "${3:-}" ]; then
    GOOS=linux GOARCH="$1" GOMIPS="$3" CGO_ENABLED=0 \
      go build -trimpath -ldflags="$LDFLAGS" -o "dist/razvilka-linux-$2" ./cmd/razvilka
  else
    GOOS=linux GOARCH="$1" CGO_ENABLED=0 \
      go build -trimpath -ldflags="$LDFLAGS" -o "dist/razvilka-linux-$2" ./cmd/razvilka
  fi
}
build amd64 amd64
build arm64 arm64
build mips mips softfloat
build mipsle mipsle softfloat
sha256sum dist/razvilka-linux-* > dist/SHA256SUMS
