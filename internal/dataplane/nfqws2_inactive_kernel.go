package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// An independent absence predicate. No queue is reserved or exempted: each
// foreign NFQUEUE row must belong to the complete OUTPUT-only graph. Empty
// registered-table coverage needs no invented mangle hooks or queue number.
func nfqws2InactiveKernelRows(snapshot BackendInventorySnapshot) ([]BackendInventoryRow, error) {
	if err := snapshot.RequireComplete(); err != nil {
		return nil, errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	queueRows := false
	var budget nfqwsDirectStockBudget
	if len(snapshot.Rows) > backendClassicRows {
		return nil, ErrNFQWSManagedKernelOwner
	}
	for _, row := range snapshot.Rows {
		if !budget.add(row) || row.Tokens[0] != "-N" && row.Tokens[0] != "-P" && row.Tokens[0] != "-A" {
			return nil, ErrNFQWSManagedKernelOwner
		}
		for i, token := range row.Tokens {
			if i > 0 && row.Tokens[i-1] == "--comment" {
				continue // Literal comment text cannot attach a queue or chain.
			}
			if strings.Contains(token, "RZQ_") || strings.HasPrefix(strings.ToLower(token), "nfqws") {
				return nil, ErrNFQWSManagedKernelOwner
			}
		}
		queueRows = queueRows || nfqwsDirectStockOtherTableQueue(row.Tokens)
	}
	if !queueRows {
		return nil, nil
	}
	rows, err := inspectStockOutputQueueGraph(snapshot, nil, nil)
	if err != nil {
		return nil, errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	return rows, nil
}

type nfqws2InactiveQueueFrame struct {
	queues []nfqwsScopedForeignQueueState
}

type nfqws2InactiveKernelReader struct {
	read    func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)
	queues  func(context.Context) ([]nfqwsScopedQueue, error)
	sockets func(context.Context) (string, error)
}

func (r nfqws2InactiveKernelReader) frame(ctx context.Context, comparison []BackendInventoryRow) (nfqws2InactiveQueueFrame, error) {
	var zero nfqws2InactiveQueueFrame
	if ctx == nil || ctx.Err() != nil || r.queues == nil || r.sockets == nil {
		return zero, ErrNFQWSManagedKernelOwner
	}
	allowed := map[uint16]bool{}
	for _, row := range comparison {
		action, err := nfqwsDirectStockRuleAction(row.Tokens)
		if err != nil || action.target != "NFQUEUE" || action.queue == nil {
			return zero, ErrNFQWSManagedKernelOwner
		}
		allowed[*action.queue] = true
	}
	queues, err := r.queues(ctx)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	sockets, err := r.sockets(ctx)
	if err != nil {
		return zero, errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	// Validate a positively read complete socket table even when queues are
	// empty. An absent proc leaf or an empty/truncated header is never absence.
	if nfqws2InactiveNetlinkTable(sockets) != nil {
		return zero, ErrNFQWSManagedKernelOwner
	}
	seen := map[uint16]bool{}
	var frame nfqws2InactiveQueueFrame
	for _, queue := range queues {
		if ctx.Err() != nil || seen[queue.number] || !allowed[queue.number] || queue.portID == 0 || queue.copyMode > 2 || queue.copyRange > 65535 {
			return zero, ErrNFQWSManagedKernelOwner
		}
		seen[queue.number] = true
		inode, err := nfqwsScopedSocketInode(sockets, queue.portID)
		if err != nil || inode == "" {
			return zero, errors.Join(ErrNFQWSManagedKernelOwner, err)
		}
		frame.queues = append(frame.queues, nfqwsScopedForeignQueueState{queue: queue, inode: inode})
	}
	slices.SortFunc(frame.queues, func(a, b nfqwsScopedForeignQueueState) int { return int(a.queue.number) - int(b.queue.number) })
	return frame, ctx.Err()
}

func (r nfqws2InactiveKernelReader) check(ctx context.Context, identity netidentity.Identity) error {
	if ctx == nil || ctx.Err() != nil || identity.Validate() != nil || r.read == nil {
		return ErrNFQWSManagedKernelOwner
	}
	before, err := r.read(ctx, identity)
	if err != nil || before.Scope.Network != identity {
		return errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	comparison, err := nfqws2InactiveKernelRows(before)
	if err != nil {
		return err
	}
	opening, err := r.frame(ctx, comparison)
	if err != nil {
		return err
	}
	after, err := r.read(ctx, identity)
	if err != nil || after.Scope.Network != identity || !reflect.DeepEqual(before, after) {
		return errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	closingComparison, err := nfqws2InactiveKernelRows(after)
	if err != nil || !reflect.DeepEqual(comparison, closingComparison) {
		return errors.Join(ErrNFQWSManagedKernelOwner, err)
	}
	closing, err := r.frame(ctx, closingComparison)
	if err != nil || !slices.Equal(opening.queues, closing.queues) || ctx.Err() != nil {
		return errors.Join(ErrNFQWSManagedKernelOwner, err, ctx.Err())
	}
	return nil
}
