package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestNodeCatalogSelectionSurvivesHealthWritesBeforeAdmission(t *testing.T) {
	a, selected := durableNodeFixture(t, 2)
	q := durableCatalogRequest(t, a)
	snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q.CatalogDigest = allVLESSCheckDigest(snapshot)
	profile, err := a.freshNetworkProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	item := a.runNodeCheckItem(context.Background(), "service", selected.NodeIDs[0], a.Catalog.Services[0], profile, nil)
	if !item.Available {
		t.Fatal(item)
	}
	after, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil || after.Generation == q.Generation {
		t.Fatal("health write missing", err)
	}
	if allVLESSCheckDigest(after) != q.CatalogDigest {
		t.Fatal("health changed selection")
	}
	id := enqueueNodeFixture(t, a, q)
	q.Generation = after.Generation
	q.IdempotencyKey = "another-catalogue-window-001"
	if enqueueNodeFixture(t, a, q) != id {
		t.Fatal("duplicate job after health mutation")
	}
	j := durableJobAt(t, a, id)
	if j.Request.NodeCatalog.SelectionDigest != q.CatalogDigest || len(j.Request.NodeIDs) != 2 {
		t.Fatal("intent lost")
	}
	raw, _ := json.Marshal(a.reconciler.doc.Jobs)
	var restored []durableServiceJob
	if json.Unmarshal(raw, &restored) != nil || validateDurableServiceJobs(restored) != nil || durableRequestFingerprint(restored[0].Request) != j.RequestHash {
		t.Fatal("selector did not survive journal encoding")
	}
}

func TestNodeCatalogSelectionRejectsMembershipChangesAndMalformedDigest(t *testing.T) {
	for _, change := range []string{"import", "disable", "delete", "invalid-digest"} {
		t.Run(change, func(t *testing.T) {
			a, selected := durableNodeFixture(t, 2)
			q := durableCatalogRequest(t, a)
			snapshot, err := a.Nodes.Snapshot(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			q.CatalogDigest = allVLESSCheckDigest(snapshot)
			switch change {
			case "import":
				_, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: "later", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@new.example:443?security=tls", time.Now(), time.Hour, false)
			case "disable":
				_, err = a.Nodes.SetDisabled(context.Background(), selected.NodeIDs[0], true, time.Now())
			case "delete":
				_, err = a.Nodes.Delete(context.Background(), selected.NodeIDs[0], time.Now())
			case "invalid-digest":
				q.CatalogDigest = "not-a-digest"
			}
			if err != nil {
				t.Fatal(err)
			}
			w := controlRequest(a, "POST", "/api/v1/node-checks", q)
			want := 409
			if change == "invalid-digest" {
				want = 400
			}
			if w.Code != want || len(a.reconciler.doc.Jobs) != 0 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestNodeCatalogSelectionIgnoresPresentationButIncludesExpiry(t *testing.T) {
	base := nodestore.Snapshot{Generation: 1, Nodes: []nodestore.Node{{ID: "node-" + strings.Repeat("a", 64), Protocol: "vless", State: "quarantined"}}}
	want := allVLESSCheckDigest(base)
	base.Generation++
	base.Nodes[0].Name = "new alias"
	base.Nodes[0].Health.State = "available"
	base.Nodes = append(base.Nodes, nodestore.Node{ID: "other", Protocol: "hysteria2"})
	if allVLESSCheckDigest(base) != want {
		t.Fatal("unrelated metadata changed selection")
	}
	base.Nodes[0].State = "expired"
	if allVLESSCheckDigest(base) == want {
		t.Fatal("expiry ignored")
	}
}
