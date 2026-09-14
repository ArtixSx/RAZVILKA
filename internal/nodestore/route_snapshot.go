package nodestore

import (
	"context"
	"sort"
	"time"

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// RouteSnapshot returns public metadata and exact eligible service IDs from
// one private-envelope generation. Keys are raw node/group IDs, including
// empty lists for ineligible entries; no endpoint or credential is returned.
func (s *Store) RouteSnapshot(ctx context.Context, profile string, now time.Time) (Snapshot, map[string][]string, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, nil, err
	}
	if !checkTokenPattern.MatchString(profile) || now.IsZero() {
		return Snapshot{}, nil, ErrStore
	}
	if !systemprobe.ValidWANProfileID(profile) {
		return Snapshot{}, nil, ErrRouteProof
	}
	if err := s.lockRouteSnapshot(ctx); err != nil {
		return Snapshot{}, nil, err
	}
	doc, _, err := s.load(ctx)
	s.mu.Unlock()
	if canceled := ctx.Err(); canceled != nil {
		return Snapshot{}, nil, canceled
	}
	if err != nil {
		return Snapshot{}, nil, err
	}
	// load decoded a detached document. Writers may proceed while all returned
	// metadata and route permissions continue to describe that same generation.
	now = now.UTC()
	services := make(map[string][]string, len(doc.Nodes)+len(doc.Groups))
	for _, node := range doc.Nodes {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, nil, err
		}
		services[node.ID] = routeServicesForNode(node, profile, now)
	}
	for _, group := range doc.Groups {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, nil, err
		}
		services[group.ID] = routeServicesForGroup(group, services)
	}
	public := snapshot(doc, now)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, nil, err
	}
	return public, services, nil
}

// Unlike an uninterruptible mutex wait, a canceled HTTP selector request must
// not remain queued behind a store mutation. No worker goroutine is created.
func (s *Store) lockRouteSnapshot(ctx context.Context) error {
	if s.mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if s.mu.TryLock() {
				return nil
			}
		}
	}
}

func routeServicesForGroup(group NodeGroup, services map[string][]string) []string {
	if group.Mode == "manual" {
		for _, member := range group.NodeIDs {
			if member == group.PreferredNodeID {
				return append([]string{}, services[member]...)
			}
		}
		return []string{}
	}
	out := []string{}
	if group.Mode != "fallback" {
		return out
	}
	seen := map[string]bool{}
	for _, member := range group.NodeIDs {
		for _, service := range services[member] {
			seen[service] = true
		}
	}
	for service := range seen {
		out = append(out, service)
	}
	sort.Strings(out)
	return out
}
