package dataplane

import (
	"bytes"
	"errors"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// NFQWS2PackageMutationBlocked only observes retained ownership. A false result
// is not permission to mutate a package or run an init action; callers retain
// their normal component writer, runtime and operation gates.
func (m *Manager) NFQWS2PackageMutationBlocked() (bool, error) {
	if m == nil || m.StateRoot == "" {
		return false, errors.New("NFQWS2 dataplane ownership is unavailable")
	}
	adapter, _ := m.adapter("nfqws2")
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a == nil {
		return false, errors.New("NFQWS2 adapter is not registered")
	}
	lease, err := a.readLease()
	if err != nil {
		return false, err
	}
	if lease != nil && lease.FirstStart != nil {
		return true, nil
	}
	data, _, err := nfqws2Read(a.InitPath)
	if err != nil {
		return false, err
	}
	if _, err := engineconfig.NFQWSFirstStartInitOwner(data); err == nil {
		return true, nil
	}
	if bytes.Contains(data, []byte("RAZVILKA NFQWS2")) || bytes.Contains(data, []byte("# RAZVILKA INSTANCE ")) {
		return false, engineconfig.ErrNFQWSFirstStart
	}
	return false, nil
}
