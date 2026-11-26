//go:build !linux

package dataplane

import (
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func offlineStopDirectoryIdentity(os.FileInfo) (string, error) { return "", ErrRuntimeInactivity }

func offlineStopPrivateFile(os.FileInfo) bool { return false }

func offlineStopOpenFile(root *ownedfs.Root, name string) (*os.File, error) {
	return nil, ErrRuntimeInactivity
}

func offlineStopNativeFileIdentity(os.FileInfo) (string, error) { return "", ErrRuntimeInactivity }
