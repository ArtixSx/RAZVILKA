package usquediag

import (
	"strings"
	"testing"
)

func TestOwnedNativeAssetValidation(t *testing.T) {
	account := `{"private_key":"TEST-ONLY-KEY","endpoint_pub_key":"TEST-ONLY-PEER","id":"TEST-ONLY-ID","access_token":"TEST-ONLY-TOKEN","endpoint_v4":"162.159.193.10","endpoint_h2_v4":"162.159.193.11"}`
	for _, tc := range []struct {
		name, account, mode, binary, arch, endpoint string
	}{
		{"h2", account, "HTTP/2", ownedFixtureExecutableSHA, "amd64", "162.159.193.11:443"},
		{"quic", account, "QUIC", ownedFixtureExecutableSHA, "amd64", "162.159.193.10:443"},
		{"unknown-executable", account, "HTTP/2", strings.Repeat("a", 64), "amd64", ""},
		{"wrong-native-arch", account, "HTTP/2", ownedFixtureExecutableSHA, "arm64", ""},
		{"unknown-mode", account, "auto", ownedFixtureExecutableSHA, "amd64", ""},
		{"missing-credentials", `{"endpoint_h2_v4":"162.159.193.11"}`, "HTTP/2", ownedFixtureExecutableSHA, "amd64", ""},
		{"duplicate-endpoint", strings.Replace(account, `"endpoint_h2_v4":`, `"endpoint_h2_v4":"162.159.193.10","endpoint_h2_v4":`, 1), "HTTP/2", ownedFixtureExecutableSHA, "amd64", ""},
		{"no-implicit-h2", strings.Replace(account, `,"endpoint_h2_v4":"162.159.193.11"`, "", 1), "HTTP/2", ownedFixtureExecutableSHA, "amd64", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, err := ValidateOwnedUSQUENativeAssets([]byte(tc.account), tc.mode, tc.binary, tc.arch)
			if tc.endpoint == "" {
				if err == nil || endpoint.IsValid() {
					t.Fatal("invalid native assets accepted")
				}
			} else if err != nil || endpoint.String() != tc.endpoint {
				t.Fatalf("endpoint %v, error %v", endpoint, err)
			}
		})
	}
}
