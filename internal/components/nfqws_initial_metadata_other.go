//go:build !linux

package components

import "os"

func nfqwsInitialMetadata(info os.FileInfo, fixture bool) error {
	return trustedManagedNFQWSOwner(info, fixture)
}
