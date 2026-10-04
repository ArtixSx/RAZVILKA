//go:build !linux

package updatecheck

import "os"

func checkPrivateDescriptorOwner(os.FileInfo) error { return ErrFileProtocol }
