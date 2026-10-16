package ownedfs

import (
	"errors"
	"os"
)

// ReadDir reads at most limit entries from the original held directory, not
// from its configured pathname. It adds no permission to open or mutate the
// root through OpenFile. A replaced pathname cannot redirect or block this read.
func (r *Root) ReadDir(limit int) ([]os.DirEntry, error) {
	if r == nil || r.fs == nil || limit < 1 || limit > 1024 {
		return nil, errors.New("bounded original directory read required")
	}
	f, err := r.fs.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(limit)
	return entries, errors.Join(readErr, f.Close())
}
