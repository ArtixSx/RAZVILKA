//go:build !razvilka_hev_altstack_lab

package components

import "testing"

func TestHEVOfficialReleasePinsUnchanged(t *testing.T) {
	spec, _ := lookup("hev-socks5-tunnel")
	for _, row := range []struct{ arch, asset, digest string }{
		{"amd64", "hev-socks5-tunnel-linux-x86_64", "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03"},
		{"arm64", "hev-socks5-tunnel-linux-arm64", "958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba"},
	} {
		got, err := hevPinnedRelease(spec, row.arch)
		if err != nil || got.Version != "2.17.1" || got.PinnedSHA256 != row.digest || got.Asset.Name != row.asset || got.Asset.URL != "https://github.com/heiher/hev-socks5-tunnel/releases/download/2.17.1/"+row.asset {
			t.Fatalf("official pin changed: %s %+v %v", row.arch, got, err)
		}
	}
}
