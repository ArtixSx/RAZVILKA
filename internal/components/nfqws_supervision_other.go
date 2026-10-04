//go:build !linux

package components

import "context"

func ReadNFQWSSupervisionIdentity() (NFQWSSupervisionIdentity, error) {
	return NFQWSSupervisionIdentity{}, ErrNFQWSSupervisionUnavailable
}

func ReadNFQWSSupervisionProcessIdentity(int) (NFQWSSupervisionIdentity, error) {
	return NFQWSSupervisionIdentity{}, ErrNFQWSSupervisionUnavailable
}

func RunNFQWSSupervision(context.Context, NFQWSSupervisionCommand, NFQWSSupervisionHooks) (NFQWSSupervisionReceipt, error) {
	return NFQWSSupervisionReceipt{}, ErrNFQWSSupervisionUnavailable
}
