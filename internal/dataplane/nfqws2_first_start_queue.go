package dataplane

import (
	"errors"
)

var errNFQWS2FirstStartQueue = errors.New("NFQWS2 owned queue is not bound to the recorded stock process")

// nfqws2FirstStartQueue is one detached observation of the owned stock queue:
// queue -> netlink port -> socket inode held by the receipt process. Copy
// mode and range are recorded only; the stock daemon's values are not
// reviewed, so they are never required. It is not an ownership receipt.
type nfqws2FirstStartQueue struct {
	Number    uint16
	PortID    uint32
	Inode     string
	CopyMode  uint8
	CopyRange uint32
}

// nfqws2FirstStartQueueBound binds exactly one registration of queue to a
// socket in descriptors (the receipt process's /proc fd link targets). Other
// registrations, such as the firmware OUTPUT delay queue, are neither
// required nor adopted; a rule delivering to queue outside the owned graph is
// refused separately by the kernel classifier.
func nfqws2FirstStartQueueBound(queues []nfqwsScopedQueue, sockets string, descriptors []string, queue uint16) (nfqws2FirstStartQueue, error) {
	var none nfqws2FirstStartQueue
	if queue == 0 || len(descriptors) > 4096 {
		return none, errNFQWS2FirstStartQueue
	}
	var registered *nfqwsScopedQueue
	for i := range queues {
		if queues[i].number != queue {
			continue
		}
		if registered != nil {
			return none, errNFQWS2FirstStartQueue
		}
		registered = &queues[i]
	}
	if registered == nil || registered.portID == 0 {
		return none, errNFQWS2FirstStartQueue
	}
	inode, err := nfqwsScopedSocketInode(sockets, registered.portID)
	if err != nil || inode == "" {
		return none, errors.Join(errNFQWS2FirstStartQueue, err)
	}
	held := 0
	for _, link := range descriptors {
		if link == "socket:["+inode+"]" {
			held++
		}
	}
	if held == 0 {
		return none, errNFQWS2FirstStartQueue
	}
	return nfqws2FirstStartQueue{Number: queue, PortID: registered.portID, Inode: inode, CopyMode: registered.copyMode, CopyRange: registered.copyRange}, nil
}
