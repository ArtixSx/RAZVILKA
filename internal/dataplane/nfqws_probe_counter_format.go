package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Implemented by the same original startup Lease used by the collector. The
// request, stored execution and observed counter text cannot choose a format.
type nfqwsProbeCounterFormatOwner interface {
	NFQWSProbeCounterProtocol(context.Context, netidentity.Identity, string) (string, error)
}

func (e *nfqwsProbeExecution) counterProtocol(ctx context.Context) (string, error) {
	if e == nil || e.self != e || e.consumer == nil || e.consumer.self != e.consumer || e.socket == nil || e.consumer.inventory.reader.Runner == nil || e.consumer.inventory.reader.CheckTools == nil {
		return "", ErrNFQWSScopedOwner
	}
	owner, ok := e.consumer.inventory.reader.Runner.(nfqwsProbeCounterFormatOwner)
	if !ok {
		return "", ErrNFQWSScopedOwner
	}
	protocol, err := owner.NFQWSProbeCounterProtocol(ctx, e.socket.identity, e.consumer.inventory.review)
	if err != nil || protocol != "6" && protocol != "tcp" {
		return "", errors.Join(ErrNFQWSScopedOwner, err)
	}
	return protocol, nil
}
