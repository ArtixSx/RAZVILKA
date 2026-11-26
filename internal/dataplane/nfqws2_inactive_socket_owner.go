package dataplane

import (
	"errors"
	"slices"
)

// The queue and netlink proc files are separate observations. Socket release
// can remove the netlink row before its queue registration is removed. Only a
// missing peer in an otherwise completely validated table gets this private
// marker; an arbitrary socket.owner refusal is not retry authority.
var errNFQWS2InactiveSocketPeerMissing = errors.New("NFQWS2 queue peer is missing from a complete socket table")

func nfqws2InactiveMissingPeerUnchanged(opening, closing nfqws2InactiveQueueFrame) bool {
	return slices.EqualFunc(opening.queues, closing.queues, func(before, after nfqwsScopedForeignQueueState) bool {
		return before.queue == after.queue && (after.inode == "" || before.inode == after.inode)
	})
}

// Accept only the exact private missing-peer branch and its ordinary closing
// wrapper. A joined source/cancellation/foreign/parse refusal or another
// ambiguity must remain terminal. No public error text supplies this marker.
func nfqws2InactiveMissingPeerRead(err error) bool {
	branch, ok := err.(*nfqws2InactiveKernelFailure)
	if !ok || branch == nil {
		return false
	}
	if branch.stage == "frame.changed" {
		joined, ok := branch.cause.(interface{ Unwrap() []error })
		if !ok {
			return false
		}
		children := joined.Unwrap()
		if len(children) != 2 || children[0] != ErrNFQWSManagedKernelOwner {
			return false
		}
		branch, ok = children[1].(*nfqws2InactiveKernelFailure)
		if !ok || branch == nil {
			return false
		}
	}
	if branch.stage != "socket.owner" {
		return false
	}
	joined, ok := branch.cause.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	children := joined.Unwrap()
	return len(children) == 3 && children[0] == ErrNFQWSManagedKernelOwner &&
		children[1] == ErrNFQWSScopedOwner && children[2] == errNFQWS2InactiveSocketPeerMissing
}
