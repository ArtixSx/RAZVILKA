//go:build !linux

package dataplane

func nfqws2InactiveSystemPlatform() (nfqws2InactivePlatform, error) {
	return nfqws2InactivePlatform{}, ErrNFQWSManagedKernelOwner
}
