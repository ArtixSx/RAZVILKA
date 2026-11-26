package community

// BrowseDefinition deliberately has no source URLs, regional access claims,
// imported state, list contents, preview digest or import authority.
type BrowseDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// BrowseDefinitions copies only bounded immutable display strings already in
// memory. It never refreshes the index, reads checkpoints or inspects previews.
// The existing mutex protects only a short copy of at most 1128 definitions;
// network refresh does not retain it while fetching or writing its checkpoint.
func (m *Manager) BrowseDefinitions() ([]BrowseDefinition, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.registry.Schema != 1 || len(m.registry.Entries) == 0 || len(m.registry.Entries) > 128 || len(m.geo) > maxGeoServices {
		return nil, false
	}
	result := make([]BrowseDefinition, 0, len(m.registry.Entries)+len(m.geo))
	bytes := 0
	for _, entries := range [][]Entry{m.registry.Entries, m.geo} {
		for _, entry := range entries {
			if !entryIDPattern.MatchString(entry.ID) || len(entry.Name) == 0 || len(entry.Name) > 512 || len(entry.Category) > 256 || len(entry.Description) > 4096 {
				return nil, false
			}
			bytes += len(entry.ID) + len(entry.Name) + len(entry.Category) + len(entry.Description)
			if bytes > 256<<10 {
				return nil, false
			}
			result = append(result, BrowseDefinition{entry.ID, entry.Name, entry.Category, entry.Description})
		}
	}
	return result, true
}
