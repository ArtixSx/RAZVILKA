package providerprofile

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestVLESSRedundantSecureAliasesPreserveVerification(t *testing.T) {
	for _, query := range []string{
		"allowInsecure=0&insecure=0", "allowInsecure=false&insecure=0",
		"insecure=no&allowInsecure=FALSE", "allowInsecure=no&insecure=false",
	} {
		result, err := ParseCanonicalURI(testVLESS + "security=tls&" + query)
		if err != nil {
			t.Fatalf("redundant explicit verification refused: %v", err)
		}
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if json.Unmarshal(result.Config, &doc) != nil || len(doc.Outbounds) != 1 {
			t.Fatal("missing canonical outbound")
		}
		tls := doc.Outbounds[0]["tls"].(map[string]any)
		if tls["enabled"] != true || tls["insecure"] == true {
			t.Fatal("certificate verification weakened")
		}
	}
	for _, query := range []string{
		"allowInsecure=1&insecure=0", "allowInsecure=0&insecure=true",
		"allowInsecure=yes&insecure=1", "allowInsecure=1&insecure=1",
		"insecure=false&insecure=false", "allowInsecure=0&allowInsecure=0",
		"allowInsecure=unknown&insecure=false", "allowInsecure=&insecure=0",
		"serverName=front.example&sni=front.example",
	} {
		for i := 0; i < 8; i++ { // Go map iteration must not turn a conflict into acceptance.
			result, err := ParseCanonicalURI(testVLESS + "security=tls&" + query)
			if err == nil || len(result.Config) != 0 {
				t.Fatal("ambiguous or insecure input accepted")
			}
		}
	}
}

// Golden values independently match pinned Xray v26.3.27 uuid.ParseString
// and Python uuid.uuid5(UUID(int=0), value); no real credential is used here.
func TestVLESSCustomIDGoldenAndBoundaries(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"hello", "b7502f40-1152-59f2-ba10-69aeed522cdf"},
		{"not-a-uuid", "9b70e619-d7b3-55b1-b743-756ebd573b4e"},
		{"vpn", "88b9a025-929f-582f-a10c-1e87718cac3f"},
		{strings.Repeat("я", 15), "01882c0c-023f-560a-9c0a-012d515f95d2"},
		{"我爱🍉老师1314", "5783a3e7-e373-51cd-8642-c83782b807c5"},
		{" hello ", "80baf4a7-61aa-5ae2-bea4-3d2630c7f202"},
		{strings.Repeat("x", 30), "53267599-dc74-5b79-bef1-55ca25ed44c9"},
		{"123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
	} {
		got, ok := normalizeVLESSID(tc.input)
		if !ok || got != tc.want {
			t.Fatal("custom authentication mapping differs from pinned contract")
		}
	}
	// Compact UUID support is outside this change; retain the canonical UUID
	// policy instead of accidentally mapping a malformed long ID as custom.
	for _, value := range []string{"", strings.Repeat("x", 31), strings.Repeat("я", 16), "bad\nID", "bad\x00ID", "bad\x7fID", string([]byte{0xff}), strings.Repeat("z", 36), "123e4567e89b12d3a456426614174000"} {
		if _, ok := normalizeVLESSID(value); ok {
			t.Fatal("invalid custom ID accepted")
		}
	}
	spaced, ok := normalizeVLESSID(" hello ")
	plain, _ := normalizeVLESSID("hello")
	if !ok || spaced == plain {
		t.Fatal("custom authentication whitespace was trimmed")
	}
	if _, ok := normalizeVLESSID(strings.Repeat("x", 30)); !ok {
		t.Fatal("30 byte pinned boundary refused")
	}
}

func TestVLESSCustomIDImportCanonicalIdentityAndRedaction(t *testing.T) {
	const id = "private-custom-auth"
	mapped, _ := normalizeVLESSID(id)
	uri := "vless://" + url.User(id).String() + "@edge.example:443?security=tls#" + id
	native := `{"outbounds":[{"type":"vless","server":"edge.example","server_port":443,"uuid":"` + id + `","tag":"` + id + `","tls":{"enabled":true}}]}`
	clash := "proxies:\n  - type: vless\n    server: edge.example\n    port: 443\n    uuid: " + id + "\n    name: " + id + "\n    tls: true\n"
	for _, input := range []string{uri, native, clash} {
		result, err := ParseCanonicalProfile(input)
		if err != nil || result.Preview.NodeCount != 1 {
			t.Fatalf("custom ID import refused: %v", err)
		}
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if json.Unmarshal(result.Config, &doc) != nil || doc.Outbounds[0]["uuid"] != mapped {
			t.Fatal("import did not retain exact mapped authentication")
		}
		preview, _ := json.Marshal(result.Preview)
		if strings.Contains(string(preview), id) || strings.Contains(string(preview), mapped) {
			t.Fatal("custom authentication leaked in public preview")
		}
	}
	if result, err := ParseCanonicalURI("tuic://hello:password@edge.example:443"); err == nil || len(result.Config) != 0 {
		t.Fatal("VLESS custom identity widened TUIC identity rules")
	}
}

func TestVLESSCustomIDCompilersUseSameAuthentication(t *testing.T) {
	const id = " hello "
	const want = "80baf4a7-61aa-5ae2-bea4-3d2630c7f202"
	uri := "vless://" + url.User(id).String() + "@edge.example:443?security=tls&sni=front.example"
	sing, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	var singDoc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(sing.Config, &singDoc) != nil || singDoc.Outbounds[0]["uuid"] != want {
		t.Fatal("sing-box authentication bytes differ")
	}
	xray, err := ParseXrayProfile(uri, 0)
	if err != nil {
		t.Fatal(err)
	}
	var xrayDoc struct {
		Outbounds []struct {
			Settings struct {
				Vnext []struct {
					Users []struct {
						ID string `json:"id"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(xray.Config, &xrayDoc) != nil || len(xrayDoc.Outbounds) == 0 || len(xrayDoc.Outbounds[0].Settings.Vnext) == 0 || len(xrayDoc.Outbounds[0].Settings.Vnext[0].Users) == 0 || xrayDoc.Outbounds[0].Settings.Vnext[0].Users[0].ID != want {
		t.Fatal("Xray authentication bytes differ")
	}
}
