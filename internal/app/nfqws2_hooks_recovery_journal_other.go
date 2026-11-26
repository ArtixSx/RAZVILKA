//go:build !linux

package app

import (
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func nfqws2HookPrivateOwner(info os.FileInfo) error { return nil }

func nfqws2HookInstallationOwner(info os.FileInfo) error { return nil }

func openNFQWS2HookFile(r *ownedfs.Root) (*os.File, error) {
	return r.OpenFile(nfqws2HookJournalName, os.O_RDONLY, 0)
}
