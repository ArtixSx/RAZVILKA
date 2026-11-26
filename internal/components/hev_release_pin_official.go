//go:build !razvilka_hev_altstack_lab

package components

import (
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

// The reviewed dialect/lifecycle is deliberately independent of upstream latest.
// AMD64 is the reviewed RAZVILKA runtime-altstack build of upstream 2.17.1.
// Its v0.20.0 asset is prepared for the planned fresh repository; public
// availability remains a release gate. ARM64 retains the official upstream pin.
func hevPinnedRelease(spec Spec, arch string) (releaseInfo, error) {
	if spec.Binary != "hev-socks5-tunnel" || spec.Repository != "https://github.com/heiher/hev-socks5-tunnel" {
		return releaseInfo{}, errors.New("invalid HEV release binding")
	}
	var asset, digest, assetURL string
	switch arch {
	case "amd64":
		asset = "razvilka-hev-2.17.1-runtime-altstack1-linux-amd64"
		digest = "1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9"
		assetURL = "https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0/" + asset
	case "arm64":
		asset = "hev-socks5-tunnel-linux-arm64"
		digest = "958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba"
		assetURL = spec.Repository + "/releases/download/" + backendprofile.ReviewedHEVVersion + "/" + asset
	default:
		return releaseInfo{}, fmt.Errorf("HEV has no reviewed Linux asset for %s", arch)
	}
	return releaseInfo{Version: backendprofile.ReviewedHEVVersion, Asset: releaseAsset{Name: asset, URL: assetURL}, PinnedSHA256: digest}, nil
}
