package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func enginePass(id, engine, probe string, at time.Time) CheckRecord {
	return CheckRecord{ProbeID: probe, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: engine + ":" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: at, ExpiresAt: at.Add(30 * time.Minute)}
}

func TestXrayEvidenceSurvivesReopenWithoutSingBoxAuthority(t *testing.T) {
	ctx := context.Background()
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	pass := enginePass(id, "xray", "xray-pass", testTime)
	if _, err := s.RecordCheck(ctx, id, pass, testTime); err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(ctx, "Резерв", "fallback", []string{id}, id, 0, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := testTime.Add(time.Minute)
	snapshot, services, err := s.RouteSnapshotForEngine(ctx, "xray", pass.NetworkProfile, now)
	if err != nil || len(services[id]) != 1 || len(services[group.ID]) != 1 || snapshot.Nodes[0].Health.RoutePathID != "xray:"+id || snapshot.Nodes[0].Health.History[0].RoutePathID != "xray:"+id {
		t.Fatalf("lost Xray evidence: %+v %v %v", snapshot, services, err)
	}
	for _, target := range []string{id, group.ID} {
		route, err := s.ResolveRouteForEngine(ctx, "xray", target, pass.ServiceID, pass.NetworkProfile, id, testTime, now)
		if err != nil || route.Route != "xray:"+id {
			t.Fatalf("engine changed during resolution: %+v %v", route, err)
		}
		if _, err := s.ResolveRoute(ctx, target, pass.ServiceID, pass.NetworkProfile, "", time.Time{}, now); !errors.Is(err, ErrRouteProof) {
			t.Fatal("Xray granted Sing-box authority", err)
		}
	}
	_, legacy, err := s.RouteSnapshot(ctx, pass.NetworkProfile, now)
	if err != nil || len(legacy[id]) != 0 || len(legacy[group.ID]) != 0 {
		t.Fatal("legacy selector widened Xray proof", err)
	}
	groupServices, err := s.GroupServicesForEngine(ctx, "xray", group.ID, pass.NetworkProfile, now)
	if err != nil || len(groupServices) != 1 {
		t.Fatal(groupServices, err)
	}
	utility, err := s.SourceUtilityForEngine(ctx, "xray", []string{"manual"}, []string{"vless"}, pass.ServiceID, pass.NetworkProfile, now)
	if err != nil || utility["manual"] != 1 {
		t.Fatal(utility, err)
	}
	utility, err = s.SourceUtility(ctx, []string{"manual"}, []string{"vless"}, pass.ServiceID, pass.NetworkProfile, now)
	if err != nil || utility["manual"] != 0 {
		t.Fatal("hint crossed engines", utility, err)
	}
	public, _ := json.Marshal(snapshot)
	for _, secret := range []string{"private-host", "private-sni", "123e4567", "SECRET_ALIAS"} {
		if bytes.Contains(public, []byte(secret)) {
			t.Fatal("public evidence leaked private material")
		}
	}
	binding := RouteBinding{ServiceID: pass.ServiceID, NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: []string{"telegram.org"}, Destinations: []string{"149.154.160.0/20"}}
	if _, err := s.MaterializeSingBox(ctx, []RouteBinding{binding}, now); !errors.Is(err, ErrRouteProof) {
		t.Fatal("wrong materializer accepted proof", err)
	}
	material, err := s.MaterializeXray(ctx, []RouteBinding{binding}, now)
	if err != nil || material.EngineID != "xray" || len(material.EndpointHosts) != 1 || material.EndpointHosts[0] != "private-host.example" {
		t.Fatal("lost material executor/endpoints", err)
	}
	var config struct {
		Outbounds []struct {
			Tag            string
			Protocol       string
			StreamSettings struct{ TLSSettings struct{ ServerName string } }
		}
		Routing struct{ Rules []map[string]any }
	}
	if json.Unmarshal(material.Config, &config) != nil || len(config.Outbounds) != 2 || config.Outbounds[0].Protocol != "blackhole" || config.Outbounds[1].Protocol != "vless" || config.Outbounds[1].StreamSettings.TLSSettings.ServerName != "private-sni.example" || len(config.Routing.Rules) != 3 || config.Routing.Rules[2]["outboundTag"] != "rz-node-block" {
		t.Fatal("wrong Xray config structure or fallback")
	}
	if _, ok := config.Routing.Rules[0]["ip"]; ok {
		t.Fatal("domain and IP combined as an AND match")
	}
	if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, pass.ExpiresAt); !errors.Is(err, ErrRouteProof) {
		t.Fatal("expired proof materialized", err)
	}
	backup, err := s.ExportPrivate(ctx)
	if err != nil || ValidatePrivateSnapshot(backup) != nil {
		t.Fatal("backup rejected Xray history", err)
	}
}

func TestEngineFailureRevokesOnlyItsOwnProof(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	id := importGood(t, s).Nodes[0].ID
	for i, engine := range []string{"xray", "sing-box"} {
		at := testTime.Add(time.Duration(i) * time.Second)
		if _, err := s.RecordCheck(ctx, id, enginePass(id, engine, engine+"-pass", at), at); err != nil {
			t.Fatal(err)
		}
	}
	fail := enginePass(id, "xray", "xray-failed", testTime.Add(2*time.Second))
	fail.Verdict, fail.State, fail.TestLevel, fail.Stage = "ERROR", "unavailable", "dns", "dns"
	if _, err := s.RecordCheck(ctx, id, fail, fail.CheckedAt); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{"xray", "sing-box"} {
		services, err := s.RouteServicesForEngine(ctx, engine, id, fail.NetworkProfile, fail.CheckedAt)
		if err != nil || (len(services) == 1) != (engine == "sing-box") {
			t.Fatal(engine, services, err)
		}
	}
	binding := RouteBinding{ServiceID: fail.ServiceID, NodeID: id, NetworkProfile: fail.NetworkProfile, Domains: []string{"telegram.org"}}
	if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, fail.CheckedAt); !errors.Is(err, ErrRouteProof) {
		t.Fatal("old Xray PASS retained", err)
	}
	if _, err := s.MaterializeSingBox(ctx, []RouteBinding{binding}, fail.CheckedAt); err != nil {
		t.Fatal("Xray local error revoked Sing-box", err)
	}
}

func TestEngineRouteGuardsAndCapabilityRejection(t *testing.T) {
	ctx := context.Background()
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	before := readBytes(t, path)
	if _, err := s.RecordCheck(ctx, id, CheckRecord{}, testTime); !errors.Is(err, ErrStore) || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("empty result from unsupported checker changed reputation", err)
	}
	for _, route := range []string{"xray:node-other", "xray:" + id + ":extra", "mihomo:" + id, "XRAY:" + id} {
		r := enginePass(id, "xray", "invalid-path", testTime)
		r.RoutePathID = route
		if _, err := s.RecordCheck(ctx, id, r, testTime); !errors.Is(err, ErrStore) || !bytes.Equal(before, readBytes(t, path)) {
			t.Fatal("invalid route changed history", err)
		}
	}
	if _, err := s.RouteServicesForEngine(ctx, "unknown", id, "wan-0123456789ab", testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatal(err)
	}
	pass := enginePass(id, "xray", "pass", testTime)
	if _, err := s.RecordCheck(ctx, id, pass, testTime); err != nil {
		t.Fatal(err)
	}
	binding := RouteBinding{ServiceID: pass.ServiceID, NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: []string{"telegram.org"}}
	for _, wrong := range []RouteBinding{
		{ServiceID: "discord", NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: binding.Domains},
		{ServiceID: pass.ServiceID, NodeID: id, NetworkProfile: "wan-ffffffffffff", Domains: binding.Domains},
	} {
		if _, err := s.MaterializeXray(ctx, []RouteBinding{wrong}, testTime); !errors.Is(err, ErrRouteProof) {
			t.Fatal("scope/network proof widened", err)
		}
	}
	if _, err := s.SetDisabled(ctx, id, true, testTime); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatal("disabled node materialized", err)
	}
	// Even a trusted but impossible proof cannot bypass the canonical compiler.
	s2, _ := setup(t)
	raw := strings.Replace(good, "security=tls", "security=tls&type=ws&path=%2Fx", 1)
	snap, err := s2.Import(ctx, manual, raw, testTime, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id2 := snap.Nodes[0].ID
	if _, err := s2.RecordCheck(ctx, id2, enginePass(id2, "xray", "impossible-pass", testTime), testTime); err != nil {
		t.Fatal(err)
	}
	binding.NodeID = id2
	if _, err := s2.MaterializeXray(ctx, []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatal("unsupported transport materialized", err)
	}
}

func TestXrayProofCannotPromoteTCPLeakOrExpiredOrigin(t *testing.T) {
	for _, mode := range []string{"transport-only", "direct-leak", "expired-origin"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := setup(t)
			id := importGood(t, s).Nodes[0].ID
			pass := enginePass(id, "xray", "proof-guard", testTime)
			now := testTime
			switch mode {
			case "transport-only":
				pass.TestLevel, pass.Stage = "transport", "transport"
			case "direct-leak":
				pass.DirectLeak = true
			case "expired-origin":
				pass.ExpiresAt = testTime.Add(2 * time.Hour)
				now = testTime.Add(90 * time.Minute)
			}
			if _, err := s.RecordCheck(ctx, id, pass, testTime); err != nil {
				t.Fatal(err)
			}
			services, err := s.RouteServicesForEngine(ctx, "xray", id, pass.NetworkProfile, now)
			if err != nil || len(services) != 0 {
				t.Fatal("weak/stale proof selectable", services, err)
			}
			binding := RouteBinding{ServiceID: pass.ServiceID, NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: []string{"telegram.org"}}
			if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, now); !errors.Is(err, ErrRouteProof) {
				t.Fatal("weak/stale proof materialized", err)
			}
		})
	}
}

func TestXrayGroupPreservesHealthyPreviousAndIgnoresOtherExecutor(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	raw := good + "\n" + strings.Replace(good, "private-host", "second-host", 1) + "\n" + strings.Replace(good, "private-host", "third-host", 1)
	snap, err := s.Import(ctx, manual, raw, testTime, time.Hour, false)
	if err != nil || len(snap.Nodes) != 3 {
		t.Fatal(err)
	}
	ids := []string{snap.Nodes[0].ID, snap.Nodes[1].ID, snap.Nodes[2].ID}
	for i, id := range ids {
		engine := "xray"
		if i == 0 {
			engine = "sing-box"
		}
		pass := enginePass(id, engine, "group-pass-"+id, testTime)
		pass.LatencyMS = int64(i * 100)
		if _, err := s.RecordCheck(ctx, id, pass, testTime); err != nil {
			t.Fatal(err)
		}
	}
	group, err := s.CreateGroup(ctx, "Резерв", "fallback", ids, ids[0], 0, testTime)
	if err != nil {
		t.Fatal(err)
	}
	// A faster/preferred node proved only by Sing-box cannot replace Xray LKG.
	resolved, err := s.ResolveRouteForEngine(ctx, "xray", group.ID, "telegram", "wan-0123456789ab", ids[2], testTime, testTime.Add(time.Minute))
	if err != nil || resolved.NodeID != ids[2] || resolved.Route != "xray:"+ids[2] || resolved.Reason != "hysteresis-hold" {
		t.Fatal(resolved, err)
	}
	group.Mode = "manual"
	if _, err := s.UpdateGroup(ctx, group, testTime); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveRouteForEngine(ctx, "xray", group.ID, "telegram", "wan-0123456789ab", "", time.Time{}, testTime); !errors.Is(err, ErrRouteProof) {
		t.Fatal("manual preference borrowed other engine", err)
	}
	_, services, err := s.RouteSnapshotForEngine(ctx, "xray", "wan-0123456789ab", testTime)
	if err != nil || len(services[group.ID]) != 0 {
		t.Fatal("manual group eligibility widened", services, err)
	}
	group.Mode, group.PreferredNodeID = "fallback", ""
	if _, err := s.UpdateGroup(ctx, group, testTime); err != nil {
		t.Fatal(err)
	}
	resolved, err = s.ResolveRouteForEngine(ctx, "xray", group.ID, "telegram", "wan-0123456789ab", "", time.Time{}, testTime)
	if err != nil || resolved.NodeID != ids[1] {
		t.Fatal("fallback crossed executor", resolved, err)
	}
}
