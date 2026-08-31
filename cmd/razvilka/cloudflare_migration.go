package main

import (
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

// Do not probe files at boot. A separate config uses its own profile location
// and cannot implicitly inherit production USQUE/WireGuard paths. An explicitly
// selected non-default WARP state directory is also eligible for copying.
func cloudflareLegacySources(configPath, warpState string) (*cloudflareprovider.LegacySources, error) {
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, cloudflareprovider.ErrLegacySource
	}
	standard := runtime.GOOS == "linux" && configPath == "/opt/etc/razvilka/config.json"
	specs := []cloudflareprovider.LegacySpec{
		{ID: "warp-profile", Label: "WARP · профиль RAZVILKA", Kind: cloudflareprovider.SourceWireGuard, Path: filepath.Join(filepath.Dir(configPath), "warp", "wgcf-profile.conf")},
	}
	if warpState != "" && (standard || filepath.Clean(warpState) != filepath.FromSlash("/opt/var/lib/razvilka/warp")) {
		root, err := filepath.Abs(warpState)
		if err != nil {
			return nil, cloudflareprovider.ErrLegacySource
		}
		specs = append(specs, cloudflareprovider.LegacySpec{ID: "wgcf-account", Label: "wgcf · аккаунт генератора WARP", Kind: cloudflareprovider.SourceWGCF, Path: filepath.Join(root, "wgcf-account.toml")})
	}
	if standard {
		specs = append(specs,
			cloudflareprovider.LegacySpec{ID: "usque-session", Label: "USQUE · session.conf", Kind: cloudflareprovider.SourceUSQUE, Path: "/opt/etc/usque/session.conf"},
			cloudflareprovider.LegacySpec{ID: "usque-config", Label: "USQUE · прежний config.json", Kind: cloudflareprovider.SourceUSQUE, Path: "/opt/etc/usque/config.json"},
			cloudflareprovider.LegacySpec{ID: "usque-state", Label: "USQUE · config.json в каталоге состояния", Kind: cloudflareprovider.SourceUSQUE, Path: "/opt/var/lib/usque/config.json"},
			cloudflareprovider.LegacySpec{ID: "wireguard-profile", Label: "WireGuard · внешний warp.conf", Kind: cloudflareprovider.SourceWireGuard, Path: "/opt/etc/wireguard/warp.conf"},
		)
	}
	return cloudflareprovider.NewLegacySources(specs)
}
