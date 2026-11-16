//go:build !razvilka_hev_altstack_lab

package components

import (
	"errors"
	"fmt"
	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

// The reviewed dialect/lifecycle is deliberately independent of upstream latest.
// Digests are from the official 2.17.1 release asset metadata, not a mirror.
func hevPinnedRelease(spec Spec, arch string) (releaseInfo, error) {
	if spec.Binary != "hev-socks5-tunnel" || spec.Repository != "https://github.com/heiher/hev-socks5-tunnel" {
		return releaseInfo{}, errors.New("invalid HEV release binding")
	}
	var asset, digest string
	switch arch {
	case "amd64":
		asset = "hev-socks5-tunnel-linux-x86_64"
		digest = "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03"
	case "arm64":
		asset = "hev-socks5-tunnel-linux-arm64"
		digest = "958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba"
	default:
		return releaseInfo{}, fmt.Errorf("HEV has no reviewed Linux asset for %s", arch)
	}
	return releaseInfo{Version: backendprofile.ReviewedHEVVersion, Asset: releaseAsset{Name: asset, URL: spec.Repository + "/releases/download/" + backendprofile.ReviewedHEVVersion + "/" + asset}, PinnedSHA256: digest}, nil
}
