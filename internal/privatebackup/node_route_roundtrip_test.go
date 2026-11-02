package privatebackup

import (
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/config"
	"reflect"
	"strings"
	"testing"
)

func TestEncryptedPrivateBackupPreservesCanonicalManualNodeSelections(t *testing.T) {
	routes := []string{"sing-box:node-" + strings.Repeat("a", 64), "xray:node-" + strings.Repeat("b", 64), "sing-box:group-" + strings.Repeat("c", 32), "xray:group-" + strings.Repeat("d", 32), "mihomo:node-" + strings.Repeat("e", 64)}
	payload := NewPayload("0.18.1-dev")
	for i, route := range routes {
		payload.Services[[]string{"first", "second", "third", "fourth", "fifth"}[i]] = config.ServiceState{Enabled: true, Route: route, Mode: route, Sources: []string{"192.168.1.42/32"}}
	}
	payload.EngineOrder = []string{"sing-box", "xray"}
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt(payload, "local-encrypted-node-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if strings.Contains(string(wire), route) {
			t.Fatal("selection leaked outside ciphertext")
		}
	}
	restored, err := Decrypt(encrypted, "local-encrypted-node-fixture-password")
	if err != nil || !reflect.DeepEqual(restored.Services, payload.Services) || !reflect.DeepEqual(restored.EngineOrder, payload.EngineOrder) {
		t.Fatal("canonical route bytes lost", err)
	}
	for _, route := range append(routes, "mihomo:group-"+strings.Repeat("f", 32), "mihomo:node-"+strings.Repeat("A", 64), "mihomo:node-"+strings.Repeat("e", 63), "mihomo:node-"+strings.Repeat("e", 64)+":extra") {
		candidate := NewPayload("0.18.1-dev")
		candidate.EngineOrder = []string{route}
		if Seal(&candidate) == nil {
			t.Fatal("node syntax entered AUTO engine order", route)
		}
	}
	for _, route := range []string{"mihomo:group-" + strings.Repeat("f", 32), "mihomo:node-" + strings.Repeat("A", 64), "mihomo:node-short", "mihomo:node-" + strings.Repeat("e", 64) + " "} {
		candidate := NewPayload("0.18.1-dev")
		candidate.Services["listed"] = config.ServiceState{Route: route}
		if Seal(&candidate) == nil {
			t.Fatal("unsupported manual route accepted", route)
		}
	}
}
