package components

import "testing"

func TestMihomoHistoricalRecognitionCannotSelectInstallation(t *testing.T) {
	for _, test := range []struct {
		version, arch string
		known         bool
	}{
		{"1.19.32", "amd64", true}, {ReviewedMihomoVersion, "amd64", true}, {ReviewedMihomoVersion, "arm64", true},
		{"1.19.32", "arm64", false}, {"1.19.32", "mipsle", false}, {"1.19.31", "amd64", false}, {"", "amd64", false},
	} {
		ref, err := mihomoInstalledRawArtifact(test.version, test.arch)
		if (err == nil) != test.known || err == nil && (len(ref.SHA256) != 64 || ref.Size < 1) {
			t.Fatal(test, ref, err)
		}
	}
	old, err := mihomoInstalledRawArtifact("1.19.32", "amd64")
	if err != nil || old.SHA256 != "3122d100e8177501776109f1a6253a694611627cf4d7c7ec82705855cf8626a8" || old.Size != 61993086 {
		t.Fatal(old, err)
	}
	current, err := mihomoPinnedRelease("amd64")
	if err != nil || current.Version != "1.19.33" || current.PinnedSHA256 != "132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323" {
		t.Fatal("historical recognition changed release selection", current, err)
	}
}
