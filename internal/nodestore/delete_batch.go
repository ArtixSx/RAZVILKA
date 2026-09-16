package nodestore

import (
	"context"
	"errors"
	"time"
)

var ErrGeneration = errors.New("node catalogue generation changed")

// DeleteBatch performs one bounded CompareAndSwap, not 512 rewrites. The caller
// must protect references in application stores with its exclusive operation
// admission; this store independently checks its generation and group members.
func (s *Store) DeleteBatch(ctx context.Context, ids []string, expected uint64, now time.Time) (Snapshot, error) {
	if len(ids) == 0 || len(ids) > MaxNodes || expected == 0 {
		return Snapshot{}, ErrStore
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validNodeID(id) || wanted[id] {
			return Snapshot{}, ErrStore
		}
		wanted[id] = true
	}
	return s.mutate(ctx, ids[0], now, func(doc *document, _ int) (bool, error) {
		if doc.Generation != expected {
			return false, ErrGeneration
		}
		found := 0
		for _, n := range doc.Nodes {
			if wanted[n.ID] {
				found++
			}
		}
		if found != len(ids) {
			return false, ErrNotFound
		}
		for _, g := range doc.Groups {
			for _, id := range g.NodeIDs {
				if wanted[id] {
					return false, ErrInUse
				}
			}
		}
		removedSecrets := map[string]bool{}
		nodes := doc.Nodes[:0]
		for _, n := range doc.Nodes {
			if wanted[n.ID] {
				removedSecrets[n.SecretRef] = true
			} else {
				nodes = append(nodes, n)
			}
		}
		doc.Nodes = nodes
		secrets := doc.Secrets[:0]
		for _, s := range doc.Secrets {
			if !removedSecrets[s.Ref] {
				secrets = append(secrets, s)
			}
		}
		doc.Secrets = secrets
		used := map[string]bool{}
		for _, n := range doc.Nodes {
			for _, origin := range n.Origins {
				used[origin.SourceID] = true
			}
		}
		sources := doc.Sources[:0]
		for _, source := range doc.Sources {
			if used[source.ID] {
				sources = append(sources, source)
			}
		}
		doc.Sources = sources
		return true, nil
	})
}
