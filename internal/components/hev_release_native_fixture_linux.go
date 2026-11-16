//go:build linux && razvilka_native_fixture

package components

// HEVNativeFixtureAsset exposes only this build's fixed asset identity to the
// isolated HTTP transport. It cannot configure or override a release pin.
func HEVNativeFixtureAsset(arch string) (url, digest string, err error) {
	spec, _ := lookup("hev-socks5-tunnel")
	info, err := hevPinnedRelease(spec, arch)
	return info.Asset.URL, info.PinnedSHA256, err
}
