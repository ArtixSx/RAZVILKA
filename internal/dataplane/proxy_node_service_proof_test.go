package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func nodeServiceProofFixtureService() catalog.Service {
	return catalog.Service{ID: "listed", Name: "Listed fixture", Category: "fixture", Strategy: []string{"xray"}, ProbeURL: "https://1.1.1.1/", CIDRs: []string{"1.1.1.0/24"}}
}

func nodeServiceProofFixtureCheck(f *nodeDefaultSourceFixture, id string) nodestore.CheckRecord {
	return nodestore.CheckRecord{ProbeID: id, ServiceID: "listed", NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + f.id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: f.now, ExpiresAt: f.now.Add(10 * time.Minute)}
}

func nodeServiceProofFixtureRecord(t *testing.T, f *nodeDefaultSourceFixture, check nodestore.CheckRecord) {
	t.Helper()
	if _, err := f.store.RecordCheck(f.ctx, f.id, check, f.now); err != nil {
		t.Fatal("actual fixture health record", err)
	}
}

func TestNodeServiceProofUsesOriginalExactRecordAndMaterial(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	exact := nodeServiceProofFixtureCheck(f, "exact")
	nodeServiceProofFixtureRecord(t, f, exact)
	// The aggregate latest health is a different service. It must neither
	// replace nor erase the latest exact eligible check in the actual history.
	other := nodeServiceProofFixtureCheck(f, "other-service")
	other.ServiceID, other.CheckedAt = "other", f.now.Add(time.Second)
	nodeServiceProofFixtureRecord(t, f, other)
	source := f.review(t, "xray")
	service := nodeServiceProofFixtureService()
	path := filepath.Join(f.root, "nodes.private.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	r, err := reviewNodeServiceProof(f.ctx, source, service, exact.NetworkProfile, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	o, err := r.Observation(f.ctx)
	if err != nil || o.NodeGeneration != 3 || o.NodeID != f.id || o.ServiceID != service.ID || o.WANProfile != exact.NetworkProfile ||
		o.CheckedAt != exact.CheckedAt || o.ExpiresAt != exact.ExpiresAt || !validNetworkPolicyGeneration(o.CompiledMaterialSHA256) || !validNetworkPolicyGeneration(o.ProofSHA256) ||
		o.ProofSHA256 == source.Reference().MaterialSHA256 || !reflect.DeepEqual(r.state.check, exact) {
		t.Fatal("original exact record/material reference missing", err)
	}
	material, err := f.store.MaterializeXray(f.ctx, []nodestore.RouteBinding{{ServiceID: service.ID, NodeID: f.id, NetworkProfile: exact.NetworkProfile, Destinations: service.CIDRs}}, f.now)
	defer clear(material.Config)
	if err != nil || nodeDefaultSourceMaterialHash(material.Config) != o.CompiledMaterialSHA256 {
		t.Fatal("reference does not bind actual Xray config", err)
	}
	service.CIDRs[0], service.Name = "0.0.0.0/0", "caller"
	o.ProofSHA256, o.NodeGeneration = "caller", 999
	if err := r.Current(f.ctx); err != nil {
		t.Fatal("detached caller data changed original reader", err)
	}
	after, err := os.ReadFile(path)
	defer clear(after)
	if err != nil || string(before) != string(after) {
		t.Fatal("reader wrote node material or check history", err)
	}
	public, _ := json.Marshal(r.state.ref)
	for _, private := range []string{"123e4567", "source-node", "source-front", f.root, "outbound"} {
		if strings.Contains(string(public), private) || strings.Contains(r.String(), private) {
			t.Fatal("eligibility reference exposed private material")
		}
	}
	if err := r.Close(); err != nil || source.Current(f.ctx) != nil {
		t.Fatal("reader closed shared original source/store", err)
	}
}

func TestNodeServiceProofRefusesMissingOrLatestIneligibleRecord(t *testing.T) {
	for _, bad := range []string{"unchecked", "wrong-engine", "wrong-service", "wrong-WAN", "latest-failure", "future", "expired", "non-service", "direct-leak"} {
		t.Run(bad, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			check := nodeServiceProofFixtureCheck(f, "candidate")
			switch bad {
			case "wrong-engine":
				check.RoutePathID = "sing-box:" + f.id
			case "wrong-service":
				check.ServiceID = "other"
			case "wrong-WAN":
				check.NetworkProfile = "wan-fedcba987654"
			case "latest-failure":
				old := nodeServiceProofFixtureCheck(f, "old-pass")
				old.CheckedAt = f.now.Add(-time.Second)
				nodeServiceProofFixtureRecord(t, f, old)
				check.Verdict, check.State = "BLOCKED", "unavailable"
			case "future":
				check.CheckedAt = f.now.Add(30 * time.Second)
			case "non-service":
				check.TestLevel = "transport"
			case "direct-leak":
				check.DirectLeak = true
			}
			if bad != "unchecked" {
				nodeServiceProofFixtureRecord(t, f, check)
			}
			if bad == "expired" {
				f.now = check.ExpiresAt
			}
			source := f.review(t, "xray")
			r, err := reviewNodeServiceProof(f.ctx, source, nodeServiceProofFixtureService(), "wan-0123456789ab", func() time.Time { return f.now })
			if r != nil {
				_ = r.Close()
			}
			if !errors.Is(err, ErrNodeServiceProof) {
				t.Fatal("ineligible real history was accepted", err)
			}
		})
	}
}

func TestNodeServiceProofRetainsExpiryAndRejectsChangedGeneration(t *testing.T) {
	for _, change := range []string{"expiry", "generation", "same-generation-record", "closed-store", "original-cancel"} {
		t.Run(change, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			check := nodeServiceProofFixtureCheck(f, "original")
			nodeServiceProofFixtureRecord(t, f, check)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			r, err := reviewNodeServiceProof(ctx, f.review(t, "xray"), nodeServiceProofFixtureService(), check.NetworkProfile, func() time.Time { return f.now })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			initial := f.now
			switch change {
			case "expiry":
				f.now = check.ExpiresAt
			case "generation":
				nodeServiceProofFixtureRecord(t, f, nodeServiceProofFixtureCheck(f, "replacement"))
			case "same-generation-record":
				backup, err := f.store.ExportPrivate(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(backup.Content)
				var envelope map[string]any
				if err := json.Unmarshal(backup.Content, &envelope); err != nil {
					t.Fatal(err)
				}
				node := envelope["nodes"].([]any)[0].(map[string]any)
				node["checks"].([]any)[0].(map[string]any)["probe_id"] = "changed-record"
				data, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(data)
				if err := os.WriteFile(filepath.Join(f.root, "nodes.private.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "closed-store":
				if err := f.store.Close(); err != nil {
					t.Fatal(err)
				}
			case "original-cancel":
				cancel()
			}
			if err := r.Current(f.ctx); !errors.Is(err, ErrNodeServiceProof) {
				t.Fatal("changed eligibility remained usable", err)
			}
			f.now = initial
			if _, err := r.Observation(f.ctx); !errors.Is(err, ErrNodeServiceProof) {
				t.Fatal("restored tuple revived reader", err)
			}
		})
	}
}

func TestNodeServiceProofInvalidContextsAndCopiesDoNotOwnReader(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	check := nodeServiceProofFixtureCheck(f, "original")
	nodeServiceProofFixtureRecord(t, f, check)
	r, err := ReviewNodeServiceProof(f.ctx, f.review(t, "xray"), nodeServiceProofFixtureService(), check.NetworkProfile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	copy := &NodeServiceProofReview{self: r}
	if copy.Current(f.ctx) == nil || copy.Close() == nil {
		t.Fatal("copy became original owner")
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), canceled} {
		if r.Current(ctx) == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if err := r.Current(f.ctx); err != nil {
		t.Fatal("invalid caller revoked valid original reader", err)
	}
}
