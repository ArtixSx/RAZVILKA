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

func publishManagedNFQWS(context.Context, string, string, string, func(func() error) error) error {
	return ErrManagedNFQWSBundle
}

func publicManagedNFQWSPath(string) error {
	if runtime.GOOS == "windows" {
		return nil // POSIX UID access is not claimed by the portable file model
	}
	return ErrManagedNFQWSBundle
}
