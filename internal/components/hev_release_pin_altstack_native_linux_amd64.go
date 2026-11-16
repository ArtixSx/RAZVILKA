//go:build linux && amd64 && razvilka_native_fixture && razvilka_hev_altstack_lab

package components

import (
	"errors"
	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

// Separate, compile-time LAB asset. Run43906655885 built the same bytes on
// Ubuntu24/26 from the reviewed2.17.1 source + runtime-altstack patch. No env
// overrides, production fallback or release-read-version changes.
// This owner-namespaced asset is NOT published. The isolated transport supplies
// it locally while preserving the original trusted-host downloader checks.
// Unsupported builds using the lab tag deliberately have no pin definition.
const hevAltstackLabSHA256 = "1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9"
const hevAltstackLabAsset = "razvilka-lab-hev-2.17.1-runtime-altstack1-linux-amd64"
const hevAltstackLabURL = "https://github.com/ArtixSx/RAZVILKA/releases/download/hev-runtime-altstack-lab-53fd786e/" + hevAltstackLabAsset

func hevPinnedRelease(spec Spec, arch string) (releaseInfo, error) {
	if spec.Binary != "hev-socks5-tunnel" || spec.Repository != "https://github.com/heiher/hev-socks5-tunnel" || arch != "amd64" {
		return releaseInfo{}, errors.New("HEV altstack lab requires exact amd64 source binding")
	}
	return releaseInfo{Version: backendprofile.ReviewedHEVVersion, Asset: releaseAsset{Name: hevAltstackLabAsset, URL: hevAltstackLabURL}, PinnedSHA256: hevAltstackLabSHA256}, nil
}
