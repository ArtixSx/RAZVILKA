//go:build !linux

package updatecheck

import "os"

func offlinePersistentIdentity(os.FileInfo) (offlineRetryIdentity, error) {
	return offlineRetryIdentity{}, ErrPairedOfflineRestore
}
