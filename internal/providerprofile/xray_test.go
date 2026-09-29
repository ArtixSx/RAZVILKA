package providerprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

const xrayUUID = "123e4567-e89b-12d3-a456-426614174000"

func compileXrayURI(t *testing.T, uri string) (map[string]any, XrayResult) {
	t.Helper()
	result, err := ParseXrayProfile(uri, 0)
	if err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	var document map[string]any
	if err := json.Unmarshal(result.Config, &document); err != nil {
		t.Fatal(err)
	}
	return document, result
}

// X01-T01: VLESS + REALITY + RAW/TCP with Vision keeps every required field.
func TestXrayCompilesRealityVision(t *testing.T) {
	document, result := compileXrayURI(t, "vless://"+xrayUUID+"@edge.example:443?security=reality&sni=front.example&fp=firefox&pbk=PUBLIC_KEY&sid=abcd&type=tcp&flow=xtls-rprx-vision#Home")
	outbounds := document["outbounds"].([]any)
	if len(outbounds) != 1 || result.Preview.EngineID != "xray" {
		t.Fatalf("managed Xray config must have exactly one remote exit: %s", result.Config)
	}
	out := outbounds[0].(map[string]any)
	server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	user := server["users"].([]any)[0].(map[string]any)
	stream := out["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	if out["protocol"] != "vless" || server["address"] != "edge.example" || server["port"] != float64(443) || user["id"] != xrayUUID || user["flow"] != "xtls-rprx-vision" || user["encryption"] != "none" {
		t.Fatalf("server identity lost: %v", out)
	}
	if stream["network"] != "tcp" || stream["security"] != "reality" || reality["serverName"] != "front.example" || reality["fingerprint"] != "firefox" || reality["publicKey"] != "PUBLIC_KEY" || reality["shortId"] != "abcd" {
		t.Fatalf("REALITY settings lost: %v", stream)
	}
	for _, key := range []string{"inbounds", "routing", "api", "dns", "policy", "stats"} {
		if _, ok := document[key]; ok {
			t.Fatalf("compiled config carries control surface %q", key)
		}
	}
}

// X01-T02: TLS over TCP keeps SNI and ALPN; REALITY without a fingerprint gets
// the documented default and says so.
func TestXrayCompilesTLSAndNamesDefaultFingerprint(t *testing.T) {
	document, _ := compileXrayURI(t, "vless://"+xrayUUID+"@edge.example:8443?security=tls&sni=cdn.example&alpn=h2,http/1.1#TLS")
	stream := document["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	tls := stream["tlsSettings"].(map[string]any)
	if stream["security"] != "tls" || tls["serverName"] != "cdn.example" || len(tls["alpn"].([]any)) != 2 {
		t.Fatalf("TLS settings lost: %v", stream)
	}
	_, result := compileXrayURI(t, "vless://"+xrayUUID+"@edge.example:443?security=reality&sni=front.example&pbk=KEY#NoFP")
	if !strings.Contains(strings.Join(result.Preview.Warnings, " "), "chrome") {
		t.Fatalf("silent fingerprint default: %v", result.Preview.Warnings)
	}
}

// X01-T03: unsupported sets are rejected explicitly; nothing is downgraded to
// a weaker or different transport.
func TestXrayRejectsUnsupportedProfilesExplicitly(t *testing.T) {
	for _, uri := range []string{
		"vless://" + xrayUUID + "@edge.example:443?security=reality&sni=front.example&pbk=KEY&type=grpc&serviceName=gate",
		"vless://" + xrayUUID + "@edge.example:443?security=tls&sni=cdn.example&type=ws&path=/x",
		"vless://" + xrayUUID + "@edge.example:443?security=none",
		"vless://" + xrayUUID + "@edge.example:443?security=reality&pbk=KEY&sni=front.example&packet_encoding=packetaddr",
		"hysteria2://secret@edge.example:443?sni=edge.example",
	} {
		if _, err := ParseXrayProfile(uri, 0); err == nil || ErrorCode(err) != "XRAY_UNSUPPORTED_PROFILE" {
			t.Fatalf("%s: err=%v code=%s", uri, err, ErrorCode(err))
		}
	}
	if _, err := ParseXrayProfile("vless://"+xrayUUID+"@edge.example:443?security=tls&sni=cdn.example&insecure=1", 0); err == nil {
		t.Fatal("certificate checks disabled for Xray")
	}
}

// X01-T04: one node of a subscription is compiled; secrets never reach the
// preview.
func TestXraySelectsOneSubscriptionNodeWithoutLeakingSecrets(t *testing.T) {
	subscription := "vless://" + xrayUUID + "@one.example:443?security=tls&sni=one.example#One\n" +
		"vless://223e4567-e89b-12d3-a456-426614174000@two.example:443?security=reality&sni=front.example&pbk=SECRETKEY&sid=beef#Two"
	result, err := ParseXrayProfile(subscription, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.Config), "two.example") || strings.Contains(string(result.Config), "one.example") {
		t.Fatalf("wrong node compiled: %s", result.Config)
	}
	preview, _ := json.Marshal(result.Preview)
	for _, secret := range []string{"223e4567-e89b-12d3-a456-426614174000", "SECRETKEY", "beef"} {
		if strings.Contains(string(preview), secret) {
			t.Fatalf("preview leaked %s", secret)
		}
	}
	if !strings.Contains(strings.Join(result.Preview.Warnings, " "), "один выбранный узел") {
		t.Fatal("subscription reduction not explained")
	}
}

// X01-T05: the compiled draft is attestable by the runtime identity check
// that the engine uses: one static remote VLESS exit, no DIRECT, no routing.
func TestXrayCompiledConfigIsAttestable(t *testing.T) {
	_, result := compileXrayURI(t, "vless://"+xrayUUID+"@edge.example:443?security=reality&sni=front.example&fp=chrome&pbk=KEY&type=tcp#A")
	protocol, err := routeidentity.ConfigOutbound("xray", result.Config)
	if err != nil || protocol != "vless" {
		t.Fatalf("compiled config not attestable: %q %v", protocol, err)
	}
}
