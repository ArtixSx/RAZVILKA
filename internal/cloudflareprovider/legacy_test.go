package cloudflareprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// Synthetic, deterministic test-only keys; never registered with a provider.
func usqueV1Fixture(t *testing.T) []byte {
	t.Helper()
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{1})
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(1)}
	der, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	x, y = curve.ScalarBaseMult([]byte{2})
	peer, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	cfg := usqueV1{PrivateKey: base64.StdEncoding.EncodeToString(der), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peer})), EndpointV4: "162.159.198.2", EndpointV6: "2606:4700:103::2", EndpointH2V4: "162.159.198.2", IPv4: "172.16.0.2", IPv6: "2606:4700:110::2", ID: "fixture-private-device", AccessToken: "fixture-private-token"}
	data, _ := json.Marshal(cfg)
	return data
}

func wgcfFixture() []byte {
	return []byte("access_token = 'fixture-private-token'\ndevice_id = \"fixture-private-device\" # own account\nlicense_key = ''\nprivate_key = '" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "'\n")
}

func TestLegacySchemaFactsRemainUnverifiedAndPrivate(t *testing.T) {
	for _, fixture := range []struct {
		kind, format, transport string
		data                    []byte
		addresses               int
	}{{SourceUSQUE, "usque-v1", "masque-usque", usqueV1Fixture(t), 2}, {SourceWGCF, "wgcf-account-v1", "wireguard", wgcfFixture(), 0}} {
		parsed, err := ParseImport(fixture.kind, fixture.data)
		if err != nil {
			t.Fatal(err)
		}
		view := parsed.Preview()
		if view.Format != fixture.format || view.Transport != fixture.transport || view.Verification != "imported-unverified" || len(view.PublicKeyFingerprint) != 64 || len(view.AssignedAddresses) != fixture.addresses || !view.HasAccessToken || !view.HasDeviceID {
			t.Fatalf("wrong derived metadata: %+v", view)
		}
		public, _ := json.Marshal(view)
		if strings.Contains(string(public), "fixture-private") {
			t.Fatal("legacy identifiers leaked")
		}
	}
	parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
	if view := parsed.Preview(); view.Format != "opaque-archive" || view.Transport != "" || view.PublicKeyFingerprint != "" {
		t.Fatal("old opaque copy gained transport capability")
	}
}

func TestWGCFRejectsAmbiguousUnsupportedOrRedactedTOML(t *testing.T) {
	for _, suffix := range []string{"access_token='duplicate'\n", "[table]\n", "unknown='value'\n", "device_id = 123\n"} {
		if _, err := ParseImport(SourceWGCF, append(wgcfFixture(), []byte(suffix)...)); err == nil {
			t.Fatal("invalid TOML accepted")
		}
	}
	for _, value := range []string{"***", "[REDACTED]", "with space", "with\\escape"} {
		input := bytes.ReplaceAll(wgcfFixture(), []byte("fixture-private-token"), []byte(value))
		if _, err := ParseImport(SourceWGCF, input); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}

func TestUSQUEInvalidKnownFieldsFallBackToArchiveNotCapability(t *testing.T) {
	base := usqueV1Fixture(t)
	for name, value := range map[string]string{"endpoint_v4": "127.0.0.1", "endpoint_v6": "162.159.198.2", "endpoint_h2_v4": "https://bad.example/", "ipv4": "not-an-address", "ipv6": "fe80::1%eth0", "private_key": "bad-key", "endpoint_pub_key": "bad-peer", "ID": "ambiguous-device"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			_ = json.Unmarshal(base, &fields)
			fields[name] = value
			data, _ := json.Marshal(fields)
			parsed, err := ParseImport(SourceUSQUE, data)
			if err != nil {
				t.Fatal("opaque archive compatibility broken")
			}
			if parsed.Preview().Format != "opaque-archive" {
				t.Fatal("invalid fields became transport-compatible")
			}
		})
	}
}
