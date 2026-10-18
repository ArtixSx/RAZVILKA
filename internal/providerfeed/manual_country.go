package providerfeed

import (
	"context"
	"encoding/json"
	"maps"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// RecordManualImportCountries supplements an already successful node import.
// Only allowlisted publisher-label ISO codes enter the existing country map;
// this is display metadata, never measured location or routing authority.
// Failure cannot roll back the separately committed node import.
func (m *Manager) RecordManualImportCountries(ctx context.Context, raw string) error {
	parsed, err := providerprofile.ParseCanonicalProfile(raw)
	if err != nil {
		return ErrFormat
	}
	defer clear(parsed.Config)
	// The canonical parser discards duplicate labels. Do not assign their first
	// label's geography when a discarded duplicate could contradict that claim.
	if len(parsed.Preview.Skipped) != 0 {
		return nil
	}
	var profile struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal(parsed.Config, &profile) != nil {
		return ErrFormat
	}
	materials := []json.RawMessage{}
	countries := []string{}
	index := 0
	for _, outbound := range profile.Outbounds {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(outbound, &kind) != nil {
			return ErrFormat
		}
		switch kind.Type {
		case "vless", "hysteria2", "tuic", "shadowsocks":
		default:
			continue
		}
		if index >= len(parsed.Preview.Nodes) {
			return ErrFormat
		}
		country := inferCountry(parsed.Preview.Nodes[index].Name)
		index++
		if country == "" {
			continue
		}
		material, err := canonicalOutbound(outbound)
		if err != nil {
			return ErrFormat
		}
		materials = append(materials, material)
		countries = append(countries, country)
	}
	if len(materials) == 0 {
		return nil
	}
	if m == nil {
		return ErrStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.fenced || m.storage == nil || m.nodes == nil {
		return ErrStore
	}
	ids, err := m.nodes.MatchImportedMaterials(ctx, materials)
	if err != nil {
		return ErrStore
	}
	snapshot, err := m.nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return ErrStore
	}
	manual := map[string]bool{}
	present := map[string]bool{}
	for _, node := range snapshot.Nodes {
		present[node.ID] = true
		for _, origin := range node.Origins {
			if origin.SourceID == "manual" {
				manual[node.ID] = true
			}
		}
	}
	before := m.storage.doc.Countries
	next := maps.Clone(before)
	if next == nil {
		next = map[string]string{}
	}
	for id := range next {
		if !present[id] {
			delete(next, id)
		}
	}
	for i, id := range ids {
		// A conflicting later manual label cannot silently replace an existing
		// accepted claim (which may also belong to a subscription publisher).
		if id != "" && manual[id] && next[id] == "" {
			next[id] = countries[i]
		}
	}
	if maps.Equal(before, next) {
		return nil
	}
	m.storage.doc.Countries = next
	if err := m.persistLocked(ctx); err != nil {
		m.storage.doc.Countries = before
		return err
	}
	return nil
}
