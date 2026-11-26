package nodestore

import (
	"context"
	"encoding/json"
)

// MatchImportedMaterials maps already normalized private candidate material to
// IDs already present in this store. It returns neither credentials nor labels,
// and reads the bounded store only once for a whole subscription import.
func (s *Store) MatchImportedMaterials(ctx context.Context, materials []json.RawMessage) ([]string, error) {
	if len(materials) > MaxNodes {
		return nil, ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(materials))
	for i, material := range materials {
		id := identity(doc.IdentityKey, material)
		if nodeIndex(doc, id) >= 0 {
			ids[i] = id
		}
	}
	return ids, nil
}
