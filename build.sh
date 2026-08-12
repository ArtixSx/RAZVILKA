#!/bin/sh
set -eu
mkdir -p dist
build(){
  if [ -n "${3:-}" ]; then
    GOOS=linux GOARCH="$1" GOMIPS="$3" CGO_ENABLED=0 \
      go build -trimpath -ldflags='-s -w' -o "dist/razvilka-linux-$2" ./cmd/razvilka
  else
    GOOS=linux GOARCH="$1" CGO_ENABLED=0 \
      go build -trimpath -ldflags='-s -w' -o "dist/razvilka-linux-$2" ./cmd/razvilka
  fi
}
build amd64 amd64
build arm64 arm64
build mips mips softfloat
build mipsle mipsle softfloat
sha256sum dist/razvilka-linux-* > dist/SHA256SUMS
