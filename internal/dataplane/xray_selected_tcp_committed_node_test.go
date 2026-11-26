package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Actual original Store and private profile, with the existing explicit
// recorded-check/endpoint models. This sealed reader grants no ACTIVE/Start.
func TestXraySelectedTCPCommittedNodeDoesNotRenewOriginalPASSOrApplyContext(t *testing.T) {
	x := newXrayOperationFixture(t)
	n, err := captureXraySelectedTCPCommittedNode(x.ctx, x.material)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(x.f.root, "nodes.private.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	future := x.f.now.Add(2 * time.Hour)
	expired, err := x.f.store.Snapshot(x.f.ctx, future)
	if err != nil {
		t.Fatal(err)
	}
	var nodeFound bool
	for _, node := range expired.Nodes {
		if node.ID == n.node.ID {
			nodeFound = true
			if !reflect.DeepEqual(xraySelectedTCPNodeIdentity(node), xraySelectedTCPNodeIdentity(n.node)) {
				t.Fatal("expiry changed retained original history/material identity")
			}
		}
	}
	if !nodeFound {
		t.Fatal("missing original node")
	}
	x.material.material.proof.now = func() time.Time { return future }
	x.cancel()
	fresh, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if x.material.current(fresh, false) == nil {
		t.Fatal("old Apply/proof was renewed")
	}
	if err := n.current(fresh); err != nil {
		t.Fatal("read-only original material depended on old Apply admission", err)
	}
	after, err := os.ReadFile(file)
	defer clear(after)
	finalInfo, statErr := os.Stat(file)
	if err != nil || statErr != nil || !reflect.DeepEqual(before, after) || !os.SameFile(info, finalInfo) {
		t.Fatal("retained identity rewrote evidence")
	}
}

func TestXraySelectedTCPCommittedNodeRefusesChangedOriginalStoreAndOwner(t *testing.T) {
	for _, change := range []string{"disabled", "deleted", "closed-store", "copy"} {
		t.Run(change, func(t *testing.T) {
			x := newXrayOperationFixture(t)
			n, err := captureXraySelectedTCPCommittedNode(x.ctx, x.material)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "disabled":
				_, err = x.f.store.SetDisabled(x.ctx, x.f.id, true, time.Now())
			case "deleted":
				_, err = x.f.store.Delete(x.ctx, x.f.id, x.f.now)
			case "closed-store":
				err = x.f.store.Close()
			case "copy":
				copy := *n
				n = &copy
			}
			if err != nil {
				t.Fatal(err)
			}
			if n.current(x.ctx) == nil {
				t.Fatal("changed/copy owner accepted", change)
			}
		})
	}
}
