package dataplane

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// A sealed identity of the genuinely admitted original Store/material. It
// never resolves eligibility, materializes a route, refreshes PASS or writes
// history. Expiry changes admission, while a committed child must still match
// its exact private input and source provenance under a fresh App operation.
type xraySelectedTCPCommittedNode struct {
	self         *xraySelectedTCPCommittedNode
	material     *XrayOperationMaterial
	store        *nodestore.Store
	generation   uint64
	sources      []nodestore.Source
	node         nodestore.Node
	secretSHA256 string
}

func captureXraySelectedTCPCommittedNode(ctx context.Context, m *XrayOperationMaterial) (*xraySelectedTCPCommittedNode, error) {
	if m == nil || m.self != m || m.material == nil || m.material.proof == nil || m.material.proof.source == nil || m.current(ctx, false) != nil {
		return nil, ErrXrayOperationOwner
	}
	source := m.material.proof.source
	n := &xraySelectedTCPCommittedNode{material: m, store: source.store, generation: source.ref.NodeGeneration, secretSHA256: source.ref.MaterialSHA256}
	n.self = n
	snapshot, err := n.store.Snapshot(ctx, time.Now().UTC())
	if err != nil || snapshot.Generation != n.generation {
		return nil, errors.Join(ErrXrayOperationOwner, err)
	}
	for _, candidate := range snapshot.Nodes {
		if candidate.ID == source.ref.NodeID {
			n.node = candidate
			break
		}
	}
	for _, origin := range n.node.Origins {
		for _, source := range snapshot.Sources {
			if source.ID == origin.SourceID {
				n.sources = append(n.sources, source)
			}
		}
	}
	if n.node.ID == "" || n.node.Disabled || n.current(ctx) != nil || m.current(ctx, false) != nil {
		return nil, ErrXrayOperationOwner
	}
	return n, nil
}

func xraySelectedTCPNodeIdentity(node nodestore.Node) nodestore.Node {
	// Health records and subscription freshness are observations, not the
	// identity of the admitted child. Keep source IDs and all material/permission
	// fields; current separately checks original source kinds and monotonic
	// origin timestamps. This does not grant fresh PASS or new Apply admission.
	node.State, node.Health = "", nodestore.Health{}
	node.Origins = append([]nodestore.Origin(nil), node.Origins...)
	for i := range node.Origins {
		node.Origins[i].ReceivedAt, node.Origins[i].ExpiresAt = time.Time{}, time.Time{}
	}
	return node
}

func (n *xraySelectedTCPCommittedNode) matches(snapshot nodestore.Snapshot, node nodestore.Node) bool {
	if node.Disabled || !reflect.DeepEqual(xraySelectedTCPNodeIdentity(node), xraySelectedTCPNodeIdentity(n.node)) || len(n.sources) != len(n.node.Origins) {
		return false
	}
	for i, origin := range node.Origins {
		original := n.node.Origins[i]
		if origin.ReceivedAt.Before(original.ReceivedAt) || origin.ExpiresAt.Before(original.ExpiresAt) {
			return false
		}
		found := false
		for _, source := range snapshot.Sources {
			found = found || source == n.sources[i]
		}
		if !found {
			return false
		}
	}
	return true
}

func (n *xraySelectedTCPCommittedNode) current(ctx context.Context) error {
	if n == nil || n.self != n || n.material == nil || n.material.self != n.material || n.material.closed.Load() || n.store == nil || n.material.material == nil ||
		n.material.material.proof == nil || n.material.material.proof.source == nil || n.material.material.proof.source.store != n.store || xraySelectedTCPFinite(ctx) != nil {
		return ErrXrayOperationOwner
	}
	read := func() error {
		snapshot, err := n.store.Snapshot(ctx, time.Now().UTC())
		if err != nil || snapshot.Generation < n.generation {
			return errors.Join(ErrXrayOperationOwner, err)
		}
		for _, node := range snapshot.Nodes {
			if node.ID == n.node.ID && n.matches(snapshot, node) {
				return nil
			}
		}
		return ErrXrayOperationOwner
	}
	if err := read(); err != nil {
		return err
	}
	err := n.store.WithSecret(ctx, n.node.ID, func(secret []byte) error {
		if nodeDefaultSourceMaterialHash(secret) != n.secretSHA256 || !nodeDefaultSourceSupported("xray", secret) {
			return ErrXrayOperationOwner
		}
		return ctx.Err()
	})
	return errors.Join(err, read())
}
