package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

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
		return zero, nfqws2InactiveKernelAt("frame.source", ErrNFQWSManagedKernelOwner)
	}
	allowed := map[uint16]bool{}
	for _, row := range comparison {
		action, err := nfqwsDirectStockRuleAction(row.Tokens)
		if err != nil || action.target != "NFQUEUE" || action.queue == nil {
			return zero, nfqws2InactiveKernelAt("frame.comparison", ErrNFQWSManagedKernelOwner)
		}
		allowed[*action.queue] = true
	}
	queues, err := r.queues(ctx)
	if err != nil {
		return zero, nfqws2InactiveKernelAt("queue.inventory", errors.Join(ErrNFQWSManagedKernelOwner, err))
	}
	sockets, err := r.sockets(ctx)
	if err != nil {
		return zero, nfqws2InactiveKernelAt("socket.inventory", errors.Join(ErrNFQWSManagedKernelOwner, err))
	}
	// Validate a positively read complete socket table even when queues are
	// empty. An absent proc leaf or an empty/truncated header is never absence.
	if err := nfqws2InactiveNetlinkTable(sockets); err != nil {
		return zero, nfqws2InactiveKernelAt("socket.table", err)
	}
	seen := map[uint16]bool{}
	var frame nfqws2InactiveQueueFrame
	for _, queue := range queues {
		if ctx.Err() != nil || seen[queue.number] || !allowed[queue.number] || queue.portID == 0 || queue.copyMode > 2 || queue.copyRange > 65535 {
			return zero, nfqws2InactiveKernelAt("queue.registration", ErrNFQWSManagedKernelOwner)
		}
		seen[queue.number] = true
		inode, err := nfqwsScopedSocketInode(sockets, queue.portID)
		if err != nil || inode == "" {
			return zero, nfqws2InactiveKernelAt("socket.owner", errors.Join(ErrNFQWSManagedKernelOwner, err))
		}
		frame.queues = append(frame.queues, nfqwsScopedForeignQueueState{queue: queue, inode: inode})
	}
	slices.SortFunc(frame.queues, func(a, b nfqwsScopedForeignQueueState) int { return int(a.queue.number) - int(b.queue.number) })
	if err := ctx.Err(); err != nil {
		return frame, nfqws2InactiveKernelAt("frame.context", err)
	}
	return frame, nil
}

// A proc seq_file read is not an atomic socket inventory. In particular a
// transient duplicate is ambiguous, so the parser continues to reject it. Only
// that exact observation failure may discard the ENTIRE kernel attempt and
// obtain new complete opening/closing inventories. This never replays a runtime
// command, reuses a partial frame, changes the original identity, or extends the
// caller's finite lease. The caller still brackets this with process/file and
// original source-lease checks.
func (r nfqws2InactiveKernelReader) check(ctx context.Context, identity netidentity.Identity) error {
	const attempts = 3
	for attempt := 0; ; attempt++ {
		err := r.checkOnce(ctx, identity)
		if ctx != nil && ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err == nil || attempt+1 == attempts || ctx == nil || !nfqws2InactiveDuplicateRead(err) {
			return err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
}

// Do not let a duplicate child concealed beside another refusal authorize a
// retry. These are exactly the wrappers produced by frame/checkOnce; all source,
// ownership, malformed table, foreign and cancellation leaves remain terminal.
func nfqws2InactiveDuplicateRead(err error) bool {
	duplicate, leaves, budget := 0, 0, 16
	var walk func(error) bool
	walk = func(err error) bool {
		budget--
		if err == nil || budget < 0 {
			return false
		}
		if err == ErrNFQWSManagedKernelOwner {
			leaves++
			return true
		}
		switch e := err.(type) {
		case *nfqws2InactiveKernelFailure:
			if e == nil {
				return false
			}
			switch e.stage {
			case "socket.table.duplicate":
				duplicate++
			case "socket.table", "frame.changed":
			default:
				return false
			}
			return walk(e.cause)
		case interface{ Unwrap() []error }:
			children := e.Unwrap()
			if len(children) == 0 {
				return false
			}
			for _, child := range children {
				if !walk(child) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return walk(err) && duplicate == 1 && leaves > 0
}

func (r nfqws2InactiveKernelReader) checkOnce(ctx context.Context, identity netidentity.Identity) error {
	if ctx == nil || ctx.Err() != nil || identity.Validate() != nil || r.read == nil {
		return nfqws2InactiveKernelAt("source", ErrNFQWSManagedKernelOwner)
	}
	before, err := r.read(ctx, identity)
	if err != nil || before.Scope.Network != identity {
		return nfqws2InactiveKernelAt("inventory.open", errors.Join(ErrNFQWSManagedKernelOwner, err))
	}
	comparison, err := nfqws2InactiveKernelRows(before)
	if err != nil {
		return nfqws2InactiveKernelAt("rules.open", err)
	}
	opening, err := r.frame(ctx, comparison)
	if err != nil {
		return err
	}
	after, err := r.read(ctx, identity)
	if err != nil || after.Scope.Network != identity {
		return nfqws2InactiveKernelAt("inventory.close", errors.Join(ErrNFQWSManagedKernelOwner, err))
	}
	if !reflect.DeepEqual(before, after) {
		return nfqws2InactiveKernelAt("inventory.changed", ErrNFQWSManagedKernelOwner)
	}
	closingComparison, err := nfqws2InactiveKernelRows(after)
	if err != nil || !reflect.DeepEqual(comparison, closingComparison) {
		return nfqws2InactiveKernelAt("rules.close", errors.Join(ErrNFQWSManagedKernelOwner, err))
	}
	closing, err := r.frame(ctx, closingComparison)
	if err != nil || !slices.Equal(opening.queues, closing.queues) || ctx.Err() != nil {
		return nfqws2InactiveKernelAt("frame.changed", errors.Join(ErrNFQWSManagedKernelOwner, err, ctx.Err()))
	}
	return nil
}
