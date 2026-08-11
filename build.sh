#!/bin/sh
set -eu
mkdir -p dist
build(){ GOOS=linux GOARCH="$1" CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "dist/razvilka-linux-$2" ./cmd/razvilka; }
build amd64 amd64
build arm64 arm64
build mips mips
build mipsle mipsle
sha256sum dist/razvilka-linux-* > dist/SHA256SUMS
