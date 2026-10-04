//go:build !linux

package components

func ReadNFQWSRuntimeProcessIdentity(int) (NFQWSRuntimeProcessIdentity, error) {
	return NFQWSRuntimeProcessIdentity{}, ErrNFQWSSupervisionUnavailable
}
