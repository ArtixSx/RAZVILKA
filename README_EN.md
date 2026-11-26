# RAZVILKA

Local service routing and connection diagnostics for Keenetic and Netcraze routers running Entware. The dashboard shows which services have a route and which have passed a recent service check. The autopilot runs on the router after the browser closes. [Русский](README.md) · [Download the 0.20.0-rc.128 prerelease](https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.20.0-rc.128)

## What has been tested

On a Netcraze NC‑1812 (ARM64), rc.128 passed panel installation, LAN sign-in, a public VLESS check against Telegram Web, and Stop from the panel. The first candidate timed out. A second returned the expected Telegram Web page and was saved as a reserve. The run took 2 min 42 s from enrollment. Whole-home forwarding with per-device exclusions and native VPN policies is still in development. This test covered the Telegram Web page only. [Router validation report](https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0-rc.128/validation-rc128.json)

## Clean installation

Start with Entware mounted at `/opt`. Sign in to the Entware shell as `root` over SSH. Back up an existing installation before changing it. These commands use the bootstrap script and the release archive for the same tag.

```sh
export PATH="/opt/sbin:/opt/bin:$PATH"
umask 077
opkg update &&
opkg install curl ca-certificates ca-bundle wget-ssl coreutils-sha256sum coreutils-mktemp &&
mkdir -p /opt/tmp &&
setup="$(mktemp /opt/tmp/razvilka-rc128.XXXXXX)" &&
curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 \
  -o "$setup" https://raw.githubusercontent.com/ArtixSx/RAZVILKA/v0.20.0-rc.128/scripts/bootstrap.sh &&
printf '%s  %s\n' 150bdb2243d65e2a7f9955d2bf36b3b02895bda79e2383751eee0a76c8bb2075 "$setup" | sha256sum -c - &&
RAZVILKA_VERSION=v0.20.0-rc.128 sh "$setup"
```

Run `/opt/bin/razvilka -version` to confirm `0.20.0-rc.128`. Open the private setup link from the installer on your LAN and set a password for `admin`. Finish setup on the dashboard. To try the tested scenario, enable a public VLESS source, open **Автопилот → Сервисы**, choose the built-in **Telegram Web** entry, and click **Передать Автопилоту**. The service card shows the check result and whether a LAN route was applied. [Entware archive](https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0-rc.128/RAZVILKA-entware.tar.gz) · [SHA-256](https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0-rc.128/RAZVILKA-entware.tar.gz.sha256)

RAZVILKA uses the MIT license. Third-party components retain their own licenses and attribution. [License](LICENSE) · [Third-party notices](THIRD_PARTY.md)
