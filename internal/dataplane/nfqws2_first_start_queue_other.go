//go:build !linux

package dataplane

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/components"
)

// Queue, netlink socket and process descriptor tables are Linux proc facts.
func nfqws2FirstStartQueueObserve(context.Context, *NFQWS2Adapter, *NFQWSRuntimeInactiveSource, uint16, components.NFQWSRuntimeProcessIdentity) (nfqws2FirstStartQueue, error) {
	return nfqws2FirstStartQueue{}, errNFQWS2FirstStartQueue
}
