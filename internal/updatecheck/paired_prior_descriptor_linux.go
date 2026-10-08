//go:build linux

package updatecheck

import "os"

func openPriorArchiveReadOnly(root *os.Root, name string) (*os.File, error) {
	return openPrivateReadOnly(root, name)
}

func checkPriorArchiveOwner(info os.FileInfo) error { return checkPrivateDescriptorOwner(info) }
