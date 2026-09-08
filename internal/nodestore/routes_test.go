package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestMaterializeSingBoxRequiresExactCurrentServiceProof(t *testing.T) {
	store, _ := setup(t)
	snapshot := importGood(t, store)
	id := snapshot.Nodes[0].ID
	binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: "wan-0123456789ab", Domains: []string{"telegram.org"}, Destinations: []string{"149.154.160.0/20"}}
	if _, err := store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatalf("unchecked node was materialized: %v", err)
	}
	record := CheckRecord{ProbeID: "node-check-route", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), HTTPStatus: 200, Message: "Подтверждено."}
	if _, err := store.RecordCheck(context.Background(), id, record, testTime); err != nil {
		t.Fatal(err)
	}
	services, err := store.RouteServices(context.Background(), id, "wan-0123456789ab", testTime.Add(time.Minute))
	if err != nil || len(services) != 1 || services[0] != "telegram" {
		t.Fatalf("services=%v err=%v", services, err)
	}
	material, err := store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(material.Config, []byte("123e4567-e89b-12d3-a456-426614174000")) == false {
		t.Fatal("private material was not passed to the local dataplane")
	}
	var document map[string]any
	if json.Unmarshal(material.Config, &document) != nil {
		t.Fatal("generated config is invalid JSON")
	}
	route := document["route"].(map[string]any)
	if route["final"] != "rz-node-block" || len(material.EndpointHosts) != 1 || material.EndpointHosts[0] != "private-host.example" {
		t.Fatalf("least-authority config or endpoint exclusion missing: route=%v endpoints=%v", route, material.EndpointHosts)
	}
	if _, err := store.MaterializeSingBox(context.Background(), []RouteBinding{{ServiceID: "youtube", NodeID: id, NetworkProfile: "wan-0123456789ab", Domains: []string{"youtube.com"}}}, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
		t.Fatal("telegram proof was widened to another service")
	}
	if _, err := store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, testTime.Add(2*time.Hour)); !errors.Is(err, ErrRouteProof) {
		t.Fatal("expired proof remained selectable")
	}
}

func TestNewerFailedCheckRevokesOlderRouteProof(t *testing.T) {
	for _, level := range []string{"dns", "transport", "protocol", "egress", "service"} {
		t.Run(level, func(t *testing.T) {
			testNewerFailedCheckRevokesOlderRouteProof(t, level)
		})
	}
}

func testNewerFailedCheckRevokesOlderRouteProof(t *testing.T, level string) {
	t.Helper()
	store, _ := setup(t)
	snapshot := importGood(t, store)
	id := snapshot.Nodes[0].ID
	pass := CheckRecord{ProbeID: "node-check-pass", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), LatencyMS: 25, Message: "Подтверждено."}
	if _, err := store.RecordCheck(context.Background(), id, pass, testTime); err != nil {
		t.Fatal(err)
	}
	fail := CheckRecord{ProbeID: "node-check-fail", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: level, Verdict: "ERROR", State: "unavailable", Stage: level, CheckedAt: testTime.Add(time.Minute), ExpiresAt: testTime.Add(time.Hour), Message: "Недоступно."}
	if _, err := store.RecordCheck(context.Background(), id, fail, testTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	services, err := store.RouteServices(context.Background(), id, "wan-0123456789ab", testTime.Add(2*time.Minute))
	if err != nil || len(services) != 0 {
		t.Fatalf("newer failure did not revoke selector authority: services=%v err=%v", services, err)
	}
	binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: "wan-0123456789ab", Domains: []string{"telegram.org"}}
	if _, err := store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, testTime.Add(2*time.Minute)); !errors.Is(err, ErrRouteProof) {
		t.Fatalf("older PASS survived newer failure: %v", err)
	}
	if _, err := store.ResolveRoute(context.Background(), id, "telegram", "wan-0123456789ab", "", time.Time{}, testTime.Add(2*time.Minute)); !errors.Is(err, ErrRouteProof) {
		t.Fatalf("direct node resolved after newer failure: %v", err)
	}
	for _, mode := range []string{"manual", "fallback"} {
		group, err := store.CreateGroup(context.Background(), "Group", mode, []string{id}, id, time.Minute, testTime.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if services, err := store.GroupServices(context.Background(), group.ID, "wan-0123456789ab", testTime.Add(2*time.Minute)); err != nil || len(services) != 0 {
			t.Fatalf("%s group retained failed node: services=%v err=%v", mode, services, err)
		}
		if _, err := store.ResolveRoute(context.Background(), group.ID, "telegram", "wan-0123456789ab", id, testTime, testTime.Add(2*time.Minute)); !errors.Is(err, ErrRouteProof) {
			t.Fatalf("%s group resolved after newer failure: %v", mode, err)
		}
	}
}

func TestMaterializeSingBoxRejectsConflictingDestinationOwners(t *testing.T) {
	store, _ := setup(t)
	first := importGood(t, store)
	second, err := store.Import(context.Background(), manual, "vless://123e4567-e89b-12d3-a456-426614174001@other.example:443?security=tls", testTime, time.Hour, false)
	if err != nil || len(second.Nodes) != 2 {
		t.Fatal(err)
	}
	for index, id := range []string{first.Nodes[0].ID, second.Nodes[1].ID} {
		record := CheckRecord{ProbeID: "node-check-conflict-" + string(rune('a'+index)), ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
			TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), Message: "Подтверждено."}
		if _, err := store.RecordCheck(context.Background(), id, record, testTime); err != nil {
			t.Fatal(err)
		}
	}
	bindings := []RouteBinding{
		{ServiceID: "telegram", NodeID: first.Nodes[0].ID, NetworkProfile: "wan-0123456789ab", Destinations: []string{"149.154.160.0/20"}},
		{ServiceID: "telegram", NodeID: second.Nodes[1].ID, NetworkProfile: "wan-0123456789ab", Destinations: []string{"149.154.160.0/20"}},
	}
	if _, err := store.MaterializeSingBox(context.Background(), bindings, testTime.Add(time.Minute)); !errors.Is(err, ErrRouteProof) {
		t.Fatal("two nodes received the same destination")
	}
}

func TestFallbackGroupKeepsLKGThenMovesAfterProofExpires(t *testing.T) {
	store, _ := setup(t)
	first := importGood(t, store)
	second, err := store.Import(context.Background(), manual, "vless://123e4567-e89b-12d3-a456-426614174001@other.example:443?security=tls", testTime, 2*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{first.Nodes[0].ID, second.Nodes[1].ID}
	for index, id := range ids {
		expires := testTime.Add(time.Hour)
		latency := int64(40)
		if index == 0 {
			expires = testTime.Add(30 * time.Minute)
			latency = 200
		}
		record := CheckRecord{ProbeID: "node-check-group-" + string(rune('a'+index)), ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
			TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: expires, LatencyMS: latency, Message: "Подтверждено."}
		if _, err := store.RecordCheck(context.Background(), id, record, testTime); err != nil {
			t.Fatal(err)
		}
	}
	group, err := store.CreateGroup(context.Background(), "Telegram резерв", "fallback", ids, ids[0], 10*time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	services, err := store.GroupServices(context.Background(), group.ID, "wan-0123456789ab", testTime.Add(time.Minute))
	if err != nil || len(services) != 1 || services[0] != "telegram" {
		t.Fatalf("services=%v err=%v", services, err)
	}
	kept, err := store.ResolveRoute(context.Background(), group.ID, "telegram", "wan-0123456789ab", ids[0], testTime, testTime.Add(5*time.Minute))
	if err != nil || kept.NodeID != ids[0] || kept.Reason != "hysteresis-hold" {
		t.Fatalf("lkg not held: %+v %v", kept, err)
	}
	fallback, err := store.ResolveRoute(context.Background(), group.ID, "telegram", "wan-0123456789ab", ids[0], testTime, testTime.Add(40*time.Minute))
	if err != nil || fallback.NodeID != ids[1] || fallback.Reason != "healthy-fallback" {
		t.Fatalf("failed node did not fall back: %+v %v", fallback, err)
	}
	if _, err := store.Delete(context.Background(), ids[0], testTime.Add(time.Minute)); !errors.Is(err, ErrInUse) {
		t.Fatal("group member was deleted")
	}
	if err := store.DeleteGroup(context.Background(), group.ID, testTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestRouteAuthorityRejectsLegacyNetworkProofWithoutBreakingHistory(t *testing.T) {
	store, _ := setup(t)
	snapshot := importGood(t, store)
	id := snapshot.Nodes[0].ID
	record := CheckRecord{ProbeID: "node-check-legacy-network", ServiceID: "telegram", NetworkProfile: "network-unknown", RoutePathID: "sing-box:" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), Message: "Legacy observation."}
	if _, err := store.RecordCheck(context.Background(), id, record, testTime); err != nil {
		t.Fatal(err)
	}
	listed, err := store.Snapshot(context.Background(), testTime)
	if err != nil || len(listed.Nodes[0].Health.History) != 1 || listed.Nodes[0].Health.History[0].NetworkProfile != "network-unknown" {
		t.Fatalf("legacy history became unreadable: %v", err)
	}
	group, err := store.CreateGroup(context.Background(), "Legacy group", "fallback", []string{id}, id, time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"", "network-unknown", "legacy-unscoped", "wan-0123456789ab"} {
		if services, err := store.RouteServices(context.Background(), id, profile, testTime); err == nil && len(services) != 0 {
			t.Fatalf("legacy history granted selector authority to %q", profile)
		}
		if services, err := store.GroupServices(context.Background(), group.ID, profile, testTime); err == nil && len(services) != 0 {
			t.Fatalf("legacy group granted selector authority to %q", profile)
		}
		binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: profile, Domains: []string{"telegram.org"}}
		if _, err := store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
			t.Fatalf("legacy proof materialized for %q: %v", profile, err)
		}
		for _, target := range []string{id, group.ID} {
			if _, err := store.ResolveRoute(context.Background(), target, "telegram", profile, "", time.Time{}, testTime); !errors.Is(err, ErrRouteProof) {
				t.Fatalf("legacy proof resolved for %q: %v", profile, err)
			}
		}
	}
}

func TestRouteAuthorityRequiresCurrentEpochAndNonfutureProof(t *testing.T) {
	store, _ := setup(t)
	snapshot := importGood(t, store)
	id := snapshot.Nodes[0].ID
	checkedAt := testTime.Add(time.Minute)
	record := CheckRecord{ProbeID: "node-check-current-network", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(time.Hour), Message: "Confirmed."}
	if _, err := store.RecordCheck(context.Background(), id, record, checkedAt); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		profile string
		now     time.Time
		usable  bool
	}{
		{"wan-0123456789ab", checkedAt, true},
		{"wan-ffffffffffff", checkedAt, false},
		{"wan-0123456789ab", checkedAt.Add(-time.Second), false},
		{"wan-0123456789ab", record.ExpiresAt, false},
	} {
		services, err := store.RouteServices(context.Background(), id, scenario.profile, scenario.now)
		if err != nil || (len(services) == 1) != scenario.usable {
			t.Fatalf("profile=%s now=%s services=%v err=%v", scenario.profile, scenario.now, services, err)
		}
		binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: scenario.profile, Domains: []string{"telegram.org"}}
		_, err = store.MaterializeSingBox(context.Background(), []RouteBinding{binding}, scenario.now)
		if (err == nil) != scenario.usable {
			t.Fatalf("unexpected materialization for profile=%s now=%s: %v", scenario.profile, scenario.now, err)
		}
	}
}
