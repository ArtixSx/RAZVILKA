//go:build !razvilka_hev_altstack_lab

package components

import "testing"

func TestHEVDefaultReleasePins(t *testing.T) {
	spec, _ := lookup("hev-socks5-tunnel")
	for _, row := range []struct{ arch, asset, digest, url string }{
		{"amd64", "razvilka-hev-2.17.1-runtime-altstack1-linux-amd64", "1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9", "https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0/razvilka-hev-2.17.1-runtime-altstack1-linux-amd64"},
		{"arm64", "hev-socks5-tunnel-linux-arm64", "958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba", "https://github.com/heiher/hev-socks5-tunnel/releases/download/2.17.1/hev-socks5-tunnel-linux-arm64"},
	} {
		got, err := hevPinnedRelease(spec, row.arch)
		if err != nil || got.Version != "2.17.1" || got.PinnedSHA256 != row.digest || got.Asset.Name != row.asset || got.Asset.URL != row.url {
			t.Fatalf("reviewed pin changed: %s %+v %v", row.arch, got, err)
		}
	}
	for _, arch := range []string{"", "mips", "mipsle", "386"} {
		if _, err := hevPinnedRelease(spec, arch); err == nil {
			t.Fatalf("unsupported architecture accepted: %s", arch)
		}
	}
	for _, mutate := range []func(*Spec){
		func(s *Spec) { s.Binary = "other" },
		func(s *Spec) { s.Repository = "https://github.com/ArtixSx/RAZVILKA" },
	} {
		wrong := spec
		mutate(&wrong)
		if _, err := hevPinnedRelease(wrong, "amd64"); err == nil {
			t.Fatal("vendor delivery changed upstream source binding")
		}
	}
}
