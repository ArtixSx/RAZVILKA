package dataplane

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Real Store writes and sealed material capture; recorded health and endpoint
// resolution use the existing explicit models. No process/ACTIVE/PASS grant.
func TestXraySelectedTCPCommittedNodeKeepsIdentityAcrossActualChecksAndFeedImport(t *testing.T) {
	x := newXrayOperationFixture(t)
	n, err := captureXraySelectedTCPCommittedNode(x.ctx, x.material)
	if err != nil {
		t.Fatal(err)
	}
	original := n.node
	for _, probe := range []string{"current-round-1", "reserve-round", "current-round-2"} {
		check := nodeServiceProofFixtureCheck(x.f, probe)
		snapshot, err := x.f.store.RecordCheck(x.ctx, x.f.id, check, x.f.now)
		if err != nil || snapshot.Generation <= n.generation {
			t.Fatal("ordinary actual history publication", err)
		}
		if err := n.current(x.ctx); err != nil {
			t.Fatal("ordinary history revoked the original material reader", probe, err)
		}
	}
	// Same original source refresh, then a genuinely unrelated new feed/node.
	for _, input := range []struct {
		source nodestore.Source
		raw    string
	}{
		{nodestore.Source{ID: "manual", Kind: "manual"}, nodeDefaultSourceFixtureURI},
		{nodestore.Source{ID: "new-feed", Kind: "subscription"}, "vless://123e4567-e89b-12d3-a456-426614174001@reserve.example:443?security=tls"},
	} {
		if _, err := x.f.store.Import(x.ctx, input.source, input.raw, x.f.now.Add(time.Second), time.Hour, false); err != nil {
			t.Fatal(err)
		}
		if err := n.current(x.ctx); err != nil {
			t.Fatal("ordinary import revoked unchanged original material", err)
		}
	}
	if !reflect.DeepEqual(n.node, original) {
		t.Fatal("reader adopted new source/health authority")
	}
	// Read identity does not renew original Apply/proof after a service failure.
	check := nodeServiceProofFixtureCheck(x.f, "current-failed")
	check.Verdict, check.State = "BLOCKED", "unavailable"
	check.ErrorCode = "node-service-failed"
	check.CheckedAt = x.f.now.Add(2 * time.Second)
	if _, err := x.f.store.RecordCheck(x.ctx, x.f.id, check, check.CheckedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := x.f.store.ResolveRouteForEngine(x.ctx, "xray", x.f.id, check.ServiceID, check.NetworkProfile, "", time.Time{}, check.CheckedAt); err == nil {
		t.Fatal("actual failed service retained fresh route/PASS admission")
	}
	if n.current(x.ctx) != nil || x.material.current(x.ctx, false) == nil {
		t.Fatal("observation reader renewed the original Apply/PASS")
	}
	x.cancel()
	fresh, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n.current(fresh) != nil {
		t.Fatal("original material reader depended on expired round context")
	}
}

func TestXraySelectedTCPCommittedNodeStillRefusesProvenanceAndMaterialDrift(t *testing.T) {
	x := newXrayOperationFixture(t)
	n, err := captureXraySelectedTCPCommittedNode(x.ctx, x.material)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := x.f.store.Snapshot(x.ctx, x.f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"source-kind", "removed-origin", "added-origin", "origin-rollback", "expiry-shortened", "protocol", "disabled"} {
		t.Run(change, func(t *testing.T) {
			s := snapshot
			s.Sources = append([]nodestore.Source(nil), snapshot.Sources...)
			node := n.node
			node.Origins = append([]nodestore.Origin(nil), n.node.Origins...)
			switch change {
			case "source-kind":
				s.Sources[0].Kind = "community"
			case "removed-origin":
				node.Origins = nil
			case "added-origin":
				node.Origins = append(node.Origins, nodestore.Origin{SourceID: "other"})
			case "origin-rollback":
				node.Origins[0].ReceivedAt = node.Origins[0].ReceivedAt.Add(-time.Second)
			case "expiry-shortened":
				node.Origins[0].ExpiresAt = node.Origins[0].ExpiresAt.Add(-time.Second)
			case "protocol":
				node.Protocol = "TROJAN"
			case "disabled":
				node.Disabled = true
			}
			if n.matches(s, node) {
				t.Fatal("changed comparison identity accepted", change)
			}
		})
	}
	// Actual new provenance for the SAME secret must not be silently adopted.
	if _, err := x.f.store.Import(x.ctx, nodestore.Source{ID: "other", Kind: "manual"}, nodeDefaultSourceFixtureURI, x.f.now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if n.current(x.ctx) == nil {
		t.Fatal("new actual source provenance was adopted")
	}
}
