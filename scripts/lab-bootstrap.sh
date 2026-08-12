#!/bin/sh
# Installs only the RAZVILKA control plane in Safe Mode, then runs diagnostics.
set -eu
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "[1/5] Checking clean Entware base..."
[ -d /opt ] || { echo "ERROR: /opt is missing" >&2; exit 10; }
command -v opkg >/dev/null 2>&1 || { echo "ERROR: opkg not found; install/activate Entware first" >&2; exit 11; }
[ -x /opt/etc/init.d/rc.unslung ] || echo "WARN: /opt/etc/init.d/rc.unslung not found; autostart may need Keenetic OPKG initrc setup"
[ -r /opt/etc/init.d/rc.func ] || { echo "ERROR: /opt/etc/init.d/rc.func is missing; Entware init framework is incomplete" >&2; exit 12; }
mkdir -p /opt/var/log/razvilka

echo "[2/5] Running preflight before installation..."
"$HERE/scripts/lab-preflight.sh" >/opt/var/log/razvilka/preflight-before-install.txt 2>&1 || true

echo "[3/5] Installing RAZVILKA manager in Safe Mode..."
"$HERE/scripts/install-entware.sh"

echo "[4/5] Verifying process and local API..."
sleep 1
if [ -x /opt/bin/razvilka ]; then
  LAN_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
  [ -n "$LAN_IP" ] || LAN_IP=127.0.0.1
  /opt/bin/razvilka -healthcheck "http://$LAN_IP:8787/api/v1/status" || echo "WARN: API probe failed; collect logs next"
else
  echo "WARN: RAZVILKA binary missing; skipping HTTP probe"
fi

echo "[5/5] Running post-install preflight..."
"$HERE/scripts/lab-preflight.sh" >/opt/var/log/razvilka/preflight-after-install.txt 2>&1 || true

echo ""
echo "RAZVILKA Test Lab manager is installed in SAFE MODE."
echo "No firewall, DNS, policy routes or bypass engines were changed."
echo "Reports:"
echo "  /opt/var/log/razvilka/preflight-before-install.txt"
echo "  /opt/var/log/razvilka/preflight-after-install.txt"
echo ""
echo "Next: open the Web UI and send the output of:"
echo "  cat /opt/var/log/razvilka/preflight-after-install.txt"
