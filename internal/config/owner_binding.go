package config

import (
	"context"
	"path/filepath"
)

// OwnerBinding is the configured target of this actual Store, for continuity
// comparison only. It creates no restore session, lease, file or permission.
func (s *Store) OwnerBinding(ctx context.Context) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrRevisionChanged
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.writeUncertain {
		return "", ErrRevisionChanged
	}
	path, err := filepath.Abs(s.path)
	if err != nil {
		return "", err
	}
	return RestoreBinding(path)
}
