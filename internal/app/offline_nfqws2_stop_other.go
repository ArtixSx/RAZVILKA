//go:build !linux

package app

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func offlineNFQDirectoryIdentity(os.FileInfo, bool) (string, error) { return "", ErrOfflineNFQWS2Stop }
func offlineNFQOpenFile(*ownedfs.Root, string) (*os.File, error)    { return nil, ErrOfflineNFQWS2Stop }
