package ownedfs

import (
	"errors"
	"os"
	"path/filepath"
)

// LstatChild observes one basename beneath the original held root without
// following it. A symlink, including a concurrently substituted dangling one,
// is an unsafe object rather than evidence that the child is absent. Restrict
// the name to one component so no intermediate path can hide a symlink.
func (r *Root) LstatChild(name string) (os.FileInfo, error) {
	if r == nil || r.fs == nil || !filepath.IsLocal(name) || filepath.Base(name) != name || filepath.Clean(name) == "." {
		return nil, errors.New("single owned child name required")
	}
	info, err := r.fs.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symlink in owned child")
	}
	return info, nil
}
