//go:build linux

package dataplane

import (
	"errors"
	"os"
)

func mihomoSameBootStaticPath(root *os.Root, name string) error {
	return mihomoColdFilePath(root, name)
}

func sameBootPolicyRecordIdentity(r *mihomoColdRecord) error {
	if r == nil {
		return ErrPolicyAdditionUnknown
	}
	held, e1 := r.file.Stat()
	named, e2 := r.root.Lstat(r.name)
	if e1 != nil || e2 != nil || !mihomoColdFileSame(r.info, held) || !mihomoColdFileSame(r.info, named) {
		return errors.Join(ErrPolicyAdditionUnknown, e1, e2)
	}
	return nil
}
