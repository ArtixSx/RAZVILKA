package providerprofile

import (
	"encoding/json"
	"testing"
)

func TestSingBoxRealityRuntimeDefaultPreservesCanonicalAndExplicitValues(t *testing.T) {
	for _, explicit := range []string{"", `,"utls":{"enabled":true,"fingerprint":"firefox"}`, `,"utls":{"enabled":false}`, `,"utls":null`, `,"utls":{"enabled":true,"fingerprint":"unknown-invalid"}`, `,"utls":"invalid"`} {
		raw := []byte(`{"type":"vless","server":"edge.example","server_port":443,"uuid":"private","tls":{"enabled":true,"server_name":"front.example","reality":{"enabled":true,"public_key":"private-key"}` + explicit + `}}`)
		var canonical map[string]any
		if json.Unmarshal(raw, &canonical) != nil {
			t.Fatal("fixture")
		}
		before, _ := json.Marshal(canonical)
		runtime, contract := SingBoxRuntimeOutbound(canonical)
		after, _ := json.Marshal(canonical)
		if string(before) != string(after) {
			t.Fatal("canonical material mutated")
		}
		if explicit == "" {
			utls := runtime["tls"].(map[string]any)["utls"].(map[string]any)
			if contract != SingBoxRealityUTLSContract || utls["enabled"] != true || utls["fingerprint"] != "chrome" {
				t.Fatal("default missing")
			}
		} else {
			actual, _ := json.Marshal(runtime)
			if contract != "" || string(actual) != string(before) {
				t.Fatal("explicit value replaced")
			}
		}
	}
	for _, raw := range []string{`{"type":"vless","tls":{"enabled":true}}`, `{"type":"vless","tls":{"enabled":false,"reality":{"enabled":true}}}`, `{"type":"trojan","tls":{"enabled":true,"reality":{"enabled":true}}}`} {
		var out map[string]any
		_ = json.Unmarshal([]byte(raw), &out)
		if _, contract := SingBoxRuntimeOutbound(out); contract != "" {
			t.Fatal("unrelated profile changed")
		}
	}
}

func TestRealityGenericRuntimeAndCanonicalImportRemainDistinct(t *testing.T) {
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=reality&pbk=PUBLIC_KEY&sni=front.example"
	canonical, err := ParseCanonicalURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		config   []byte
		defaults bool
	}{{canonical.Config, false}, {runtime.Config, true}} {
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if json.Unmarshal(item.config, &doc) != nil {
			t.Fatal("invalid compiler output")
		}
		_, found := doc.Outbounds[0]["tls"].(map[string]any)["utls"]
		if found != item.defaults {
			t.Fatal("canonical/runtime default boundary changed")
		}
	}
}
