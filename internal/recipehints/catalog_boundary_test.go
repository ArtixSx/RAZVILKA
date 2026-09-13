package recipehints

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func signedPayload(t *testing.T, payload []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	// Keep the exact payload bytes: json.Marshal(RawMessage) can compact them.
	return []byte(`{"key_id":"release-1","payload":` + string(payload) + `,"signature":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload)) + `"}`)
}

func TestSignedCatalogRejectsAmbiguousFields(t *testing.T) {
	d, pub, key, now := fixture(t)
	payload, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, from, to string
	}{
		{"document-case-alias", `"schema":1`, `"SCHEMA":1`},
		{"document-case-duplicate", `"sequence":5`, `"sequence":1,"SEQUENCE":5`},
		{"nested-case-alias", `"service_id":"youtube"`, `"SERVICE_ID":"youtube"`},
		{"nested-case-duplicate", `"failures":10`, `"failures":999999,"FAILURES":10`},
		{"missing-failure-denominator", `"failures":10,`, ``},
		{"null-failure-denominator", `"failures":10`, `"failures":null`},
		{"missing-revocations", `,"revoked":[]`, ``},
		{"null-revocations", `"revoked":[]`, `"revoked":null`},
		{"null-optional-strategy", `"strategy_id":"tls-modern-1"`, `"strategy_id":null`},
		{"null-aggregate", `"recipes":[`, `"recipes":[null,`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := bytes.Replace(payload, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(changed, payload) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := Verify(signedPayload(t, changed, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now); err == nil {
				t.Fatal("ambiguous signed catalog accepted")
			}
		})
	}
	valid := signedPayload(t, payload, key)
	for _, fromTo := range [][2]string{
		{`"key_id":"release-1"`, `"KEY_ID":"release-1"`},
		{`"key_id":"release-1"`, `"key_id":"untrusted","KEY_ID":"release-1"`},
	} {
		changed := bytes.Replace(valid, []byte(fromTo[0]), []byte(fromTo[1]), 1)
		if _, err := Verify(changed, map[string]ed25519.PublicKey{"release-1": pub}, 4, now); err == nil {
			t.Fatal("ambiguous key selection accepted")
		}
	}
}

func TestCatalogSchemaAllowsExplicitZeroAndOptionalAbsence(t *testing.T) {
	d, pub, key, now := fixture(t)
	d.Recipes[0].Failures = 0
	v, err := Verify(signed(t, d, key), map[string]ed25519.PublicKey{"release-1": pub}, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{AllowedProviders: map[string]bool{"cloudflare": true}, AllowedTraffic: map[string]bool{"nfqws2": true}, AllowedStrategies: map[string]bool{"tls-modern-1": true}, Limit: 3}
	out := v.Shortlist(Context{ServiceID: "youtube", Scenario: "web", CompatibilityID: "nfqws2-v1", Family: "ipv4"}, p, now)
	if len(out) != 1 || !out[0].LocalCheckRequired || out[0].EligibleForApply {
		t.Fatalf("explicit zero failures lost its bounded recommendation: %+v", out)
	}
}

func TestStrictSchemaStillVerifiesExactSignedBytes(t *testing.T) {
	d, pub, key, now := fixture(t)
	payload, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, payload, "", "  "); err != nil {
		t.Fatal(err)
	}
	data := signedPayload(t, formatted.Bytes(), key)
	if _, err := Verify(data, map[string]ed25519.PublicKey{"release-1": pub}, 4, now); err != nil {
		t.Fatal("schema validation changed the signed payload bytes")
	}
	changed := bytes.Replace(data, []byte(`"sequence": 5`), []byte(`"sequence":5`), 1)
	if bytes.Equal(data, changed) {
		t.Fatal("fixture mutation did not apply")
	}
	if _, err := Verify(changed, map[string]ed25519.PublicKey{"release-1": pub}, 4, now); err == nil {
		t.Fatal("same decoded document bypassed exact-byte signature verification")
	}
}
