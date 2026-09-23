package nodestore

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// SourceUtility counts distinct configured servers with current exact service
// proof and fresh provenance in each allowed source. This is only a scheduling
// hint: it grants no route authority and exports no server/credential material.
// Failed checks do not create a source penalty (the local runtime may be broken).
func (s *Store) SourceUtility(ctx context.Context, allowed, protocols []string, service, profile string, now time.Time) (map[string]int, error) {
	if len(allowed) > MaxSources || len(protocols) > 16 || !sourcePattern.MatchString(service) || now.IsZero() {
		return nil, ErrStore
	}
	if !systemprobe.ValidWANProfileID(profile) {
		return nil, ErrRouteProof
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.lockRouteSnapshot(ctx); err != nil {
		return nil, err
	}
	doc, _, err := s.load(ctx)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	servers := map[string]map[string]bool{}
	for _, id := range allowed {
		if !sourcePattern.MatchString(id) {
			return nil, ErrStore
		}
		servers[id] = map[string]bool{}
	}
	secrets := map[string]json.RawMessage{}
	for _, secret := range doc.Secrets {
		secrets[secret.Ref] = secret.Outbound
	}
	for _, node := range doc.Nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !slices.Contains(routeServicesForNode(node, profile, now), service) {
			continue
		}
		var material struct {
			Server string `json:"server"`
			Type   string `json:"type"`
		}
		if json.Unmarshal(secrets[node.SecretRef], &material) != nil || material.Server == "" {
			return nil, ErrStore
		}
		if !slices.Contains(protocols, strings.ToLower(material.Type)) {
			continue
		}
		server := reserveServerIdentity(material.Server)
		for _, origin := range node.Origins {
			if seen, ok := servers[origin.SourceID]; ok && !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt) {
				seen[server] = true
			}
		}
	}
	out := make(map[string]int, len(servers))
	for id, seen := range servers {
		out[id] = len(seen)
	}
	return out, nil
}
