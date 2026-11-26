package nodestore

import (
	"context"
	"os"
)

// OwnerRoot reads the actual original Store root descriptor and configured
// target binding. Metadata cannot reopen/recreate this owner or grant consent.
// It lets admission corroborate the current configured pathname with the SAME
// root used by Snapshot/WithSecret, without creating a restore/writer session.
func (s *Store) OwnerRoot(ctx context.Context) (string, os.FileInfo, error) {
	if s == nil || ctx == nil {
		return "", nil, ErrStore
	}
	if err := s.lockRouteSnapshot(ctx); err != nil {
		return "", nil, err
	}
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if s.closed || s.fenced {
		return "", nil, ErrStore
	}
	info, err := s.root.RootInfo()
	if err != nil {
		return "", nil, ErrStore
	}
	return s.binding, info, ctx.Err()
}
