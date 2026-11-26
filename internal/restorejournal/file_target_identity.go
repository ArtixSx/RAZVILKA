package restorejournal

import "os"

// ParentIdentity observes the actual held directory, never a pathname reopen.
// Metadata is comparison data only and grants no lease, write or deletion.
func (f *FileTarget) ParentIdentity() (os.FileInfo, error) {
	if f == nil {
		return nil, ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.root == nil {
		return nil, ErrUnavailable
	}
	if err := f.checkExistingLease(); err != nil {
		return nil, err
	}
	return f.root.RootInfo()
}
