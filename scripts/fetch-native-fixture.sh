#!/bin/sh
set -eu

# Disposable native labs only. Fixed official release assets and existing pins;
# never a production installer, a latest-version lookup or an alternate mirror.
test "$#" = 2 || { echo 'usage: fetch-native-fixture.sh ASSET OUTPUT' >&2; exit 2; }
fixture_name=$1
fixture_output=$2
case "$fixture_name" in
  xray-26.10.31)
    fixture_repo=XTLS/Xray-core
    fixture_release=v26.10.31/Xray-linux-64.zip
    fixture_asset=695486844
    fixture_sha=e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 ;;
  xray-26.3.27)
    fixture_repo=XTLS/Xray-core
    fixture_release=v26.3.27/Xray-linux-64.zip
    fixture_asset=383041956
    fixture_sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;;
  mihomo-1.19.33)
    fixture_repo=MetaCubeX/mihomo
    fixture_release=v1.19.33/mihomo-linux-amd64-v1.19.33.gz
    fixture_asset=663189133
    fixture_sha=132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323 ;;
  hev-2.17.1)
    fixture_repo=heiher/hev-socks5-tunnel
    fixture_release=2.17.1/hev-socks5-tunnel-linux-x86_64
    fixture_asset=511777659
    fixture_sha=a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03 ;;
  zapret2-1.0.6)
    fixture_repo=bol-van/zapret2
    fixture_release=v1.0.6/zapret2-v1.0.6.tar.gz
    fixture_asset=662019861
    fixture_sha=eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4 ;;
  *) echo 'unknown pinned native fixture' >&2; exit 2 ;;
esac
case "$fixture_output" in /*) ;; *) echo 'absolute fixture output required' >&2; exit 2 ;; esac
umask 077
fixture_temp=$(mktemp "${fixture_output}.download.XXXXXX")
trap 'rm -f -- "$fixture_temp"' EXIT
trap 'exit 1' HUP INT TERM
if ! curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 \
  --output "$fixture_temp" "https://github.com/$fixture_repo/releases/download/$fixture_release"; then
  echo "native_fixture=$fixture_name transport=official-release-assets-api" >&2
  curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 \
    -H 'Accept: application/octet-stream' --output "$fixture_temp" \
    "https://api.github.com/repos/$fixture_repo/releases/assets/$fixture_asset"
fi
# A successful HTTP response with wrong bytes is a hard failure, not a reason
# to try a different artifact. Publish only after the original pin matches.
printf '%s  %s\n' "$fixture_sha" "$fixture_temp" | sha256sum --check --strict
mv -f -- "$fixture_temp" "$fixture_output"
