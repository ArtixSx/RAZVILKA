//go:build linux && amd64 && razvilka_native_fixture && razvilka_hev_altstack_lab

package components

import "testing"

func TestHEVAltstackLabExactPin(t *testing.T) {
	spec, _ := lookup("hev-socks5-tunnel")
	got, err := hevPinnedRelease(spec, "amd64")
	if err != nil || got.Version != "2.17.1" || got.PinnedSHA256 != "1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9" || got.Asset.Name != "razvilka-lab-hev-2.17.1-runtime-altstack1-linux-amd64" || got.Asset.URL != "https://razvilka-altstack-lab.invalid/53fd786e6ab49bc470657943a5c0b1229d7a3b07/razvilka-lab-hev-2.17.1-runtime-altstack1-linux-amd64" {
		t.Fatalf("lab pin drift: %+v %v", got, err)
	}
	for _, arch := range []string{"arm64", "mips", "mipsle", ""} {
		if _, err := hevPinnedRelease(spec, arch); err == nil {
			t.Fatal("unsupported lab architecture", arch)
		}
	}
	for _, wrong := range []Spec{{Binary: "hev-socks5-tunnel", Repository: "https://example.invalid"}, {Binary: "foreign", Repository: spec.Repository}} {
		if _, err := hevPinnedRelease(wrong, "amd64"); err == nil {
			t.Fatal("foreign spec accepted")
		}
	}
	url, digest, err := HEVNativeFixtureAsset("amd64")
	if err != nil || url != got.Asset.URL || digest != got.PinnedSHA256 {
		t.Fatal("fixture identity drift")
	}
	t.Log("HEV_ALTSTACK_LAB_COMPILE_PIN exact reviewed source-build bytes; production pin unchanged")
}
