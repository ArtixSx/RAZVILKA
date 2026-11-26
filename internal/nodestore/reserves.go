package nodestore

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
)

// SelectReserveIDs keeps the first supplied candidate (the healthy primary,
// when present) and chooses distinct configured servers. Protocol, transport
// and source variety break subsequent ties. It grants no health or route proof.
// Hostnames, credentials and grouping identities never leave the private store.
// Different hostnames can alias one machine; this is not an operator/ASN proof.
func (s *Store) SelectReserveIDs(ctx context.Context, ordered []string, limit int) ([]string, error) {
	if len(ordered) > MaxNodes || limit < 1 || limit > 4 {
		return nil, ErrCapacity
	}
	if len(ordered) == 0 {
		return []string{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id, server, protocol, transport string
		sources                         []string
	}
	secrets := map[string]json.RawMessage{}
	for _, secret := range doc.Secrets {
		secrets[secret.Ref] = secret.Outbound
	}
	seen := map[string]bool{}
	var candidates []candidate
	for _, id := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		i := nodeIndex(doc, id)
		if i < 0 {
			return nil, ErrNotFound
		}
		node := doc.Nodes[i]
		var material struct {
			Server    string `json:"server"`
			Type      string `json:"type"`
			Transport struct {
				Type string `json:"type"`
			} `json:"transport"`
		}
		if json.Unmarshal(secrets[node.SecretRef], &material) != nil || material.Server == "" {
			return nil, ErrStore
		}
		server := reserveServerIdentity(material.Server)
		c := candidate{id: id, server: server, protocol: material.Type, transport: material.Transport.Type}
		for _, origin := range node.Origins {
			c.sources = append(c.sources, origin.SourceID)
		}
		candidates = append(candidates, c)
	}
	servers, protocols, transports, sources := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	selected := []string{}
	for len(selected) < limit {
		best, score := -1, -1
		for i, c := range candidates {
			if servers[c.server] {
				continue
			}
			value := 0
			if !protocols[c.protocol] {
				value += 4
			}
			if !transports[c.transport] {
				value += 2
			}
			for _, source := range c.sources {
				if !sources[source] {
					value++
					break
				}
			}
			if best < 0 || value > score {
				best, score = i, value
			}
			if len(selected) == 0 {
				break
			} // Never displace a healthy primary for variety.
		}
		if best < 0 {
			break
		}
		c := candidates[best]
		selected = append(selected, c.id)
		servers[c.server] = true
		protocols[c.protocol] = true
		transports[c.transport] = true
		for _, source := range c.sources {
			sources[source] = true
		}
	}
	return selected, nil
}

func reserveServerIdentity(server string) string {
	server = strings.ToLower(strings.TrimSuffix(server, "."))
	if ip, err := netip.ParseAddr(server); err == nil {
		return ip.Unmap().String()
	}
	return server
}
