package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func TestRealityRuntimeDefaultRequiresMatchingProofAndPreservesCanonical(t *testing.T) {
	store, _ := setup(t)
	ctx := context.Background()
	snapshot, err := store.Import(ctx, manual, "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=reality&pbk=PUBLIC_KEY&sni=front.example", testTime, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	var before []byte
	_ = store.WithSecret(ctx, id, func(raw []byte) error { before = bytes.Clone(raw); return nil })
	binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: "wan-0123456789ab", Domains: []string{"telegram.org"}}
	pass := CheckRecord{ProbeID: "old-proof", ServiceID: "telegram", NetworkProfile: binding.NetworkProfile, RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}
	if _, err = store.RecordCheck(ctx, id, pass, testTime); err != nil {
		t.Fatal(err)
	}
	if _, err = store.MaterializeSingBox(ctx, []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatal("old proof authorized changed default", err)
	}
	pass.ProbeID = "new-proof"
	pass.CheckedAt = testTime.Add(time.Second)
	pass.RuntimeContract = providerprofile.SingBoxRealityUTLSContract
	if _, err = store.RecordCheck(ctx, id, pass, testTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	material, err := store.MaterializeSingBox(ctx, []RouteBinding{binding}, testTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	_ = json.Unmarshal(material.Config, &doc)
	utls := doc.Outbounds[0]["tls"].(map[string]any)["utls"].(map[string]any)
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" {
		t.Fatal("route runtime default missing")
	}
	if err = store.WithSecret(ctx, id, func(raw []byte) error {
		if !bytes.Equal(before, raw) {
			t.Fatal("canonical profile/hash changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pass.ProbeID = "invalid-contract"
	pass.RuntimeContract = "private-unknown-contract"
	if _, err = store.RecordCheck(ctx, id, pass, testTime.Add(time.Second)); !errors.Is(err, ErrStore) {
		t.Fatal("unknown contract accepted", err)
	}
}
