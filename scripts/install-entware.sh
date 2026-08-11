#!/bin/sh
set -eu
umask 077
BASE=/opt
APPDIR=$BASE/etc/razvilka
CACHEDIR=$BASE/var/cache/razvilka
BINDIR=$BASE/bin
INITDIR=$BASE/etc/init.d
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  aarch64|arm64) ARCH=arm64 ;;
  mips) ARCH=mips ;;
  mipsel|mipsle) ARCH=mipsle ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BIN="$HERE/dist/razvilka-linux-$ARCH"
[ -f "$BIN" ] || { echo "Binary not found: $BIN" >&2; exit 1; }
mkdir -p "$APPDIR" "$CACHEDIR" "$BINDIR" "$INITDIR"
cp "$BIN" "$BINDIR/razvilka"
chmod 755 "$BINDIR/razvilka"
[ -f "$APPDIR/config.json" ] || cp "$HERE/configs/config.example.json" "$APPDIR/config.json"
cp "$HERE/configs/service-catalog.json" "$APPDIR/service-catalog.json"
cp "$HERE/configs/sources.json" "$APPDIR/sources.json"
chmod 600 "$APPDIR/config.json" "$APPDIR/service-catalog.json" "$APPDIR/sources.json"
cp "$HERE/scripts/S99razvilka" "$INITDIR/S99razvilka"
chmod 755 "$INITDIR/S99razvilka"
if ! "$INITDIR/S99razvilka" restart; then
  "$INITDIR/S99razvilka" start
fi
WAN_DEV="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
LAN_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
if [ -z "$LAN_IP" ]; then
  LAN_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk -v wan="$WAN_DEV" '$2 != wan {split($4,a,"/"); if (a[1] ~ /^10\./ || a[1] ~ /^192\.168\./ || a[1] ~ /^172\.(1[6-9]|2[0-9]|3[01])\./) {print a[1]; exit}}')"
fi
[ -n "$LAN_IP" ] || LAN_IP="127.0.0.1"
echo ""
echo "RAZVILKA v0.0.7-control-lab installed."
echo "Open: http://$LAN_IP:8787"
echo "Safe Mode is ON: RAZVILKA does not modify firewall, DNS or routes yet."
