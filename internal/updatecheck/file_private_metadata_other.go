//go:build !linux

package updatecheck

import "os"

func openPrivateReadOnly(*os.Root, string) (*os.File, error) { return nil, ErrFileProtocol }

func checkPrivateDescriptorOwner(os.FileInfo) error { return ErrFileProtocol }
