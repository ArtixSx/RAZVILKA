//go:build !linux

package components

import (
	"context"
	"os"
	"runtime"
)

func syncBundleFile(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil // isolated model fixtures only; publication remains unavailable
	}
	return f.Sync()
}

func chmodBundleDirectory(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil // portable fixture directories, no production publication
	}
	return f.Chmod(0555)
}

func publishManagedNFQWS(context.Context, string, string, string, func(func() error) error, func(string) error) error {
	return ErrManagedNFQWSBundle
}

func trustedManagedNFQWSOwner(_ os.FileInfo, fixture bool) error {
	if runtime.GOOS == "windows" && fixture {
		return nil // POSIX UID access is not claimed by the portable file model
	}
	return ErrManagedNFQWSBundle
}

func managedNFQWSPublicTraversal(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0001 != 0
}

func managedNFQWSNodeDescription(os.FileInfo) string { return "POSIX ownership unavailable" }
