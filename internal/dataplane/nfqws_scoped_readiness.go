package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/ArtixSx/razvilka/internal/components"
)

// This phase is read-only and receives the issuer's retained Current guard.
// It requires the same exact running proof around LAN and all-capture reads.
// Ready can change only from positively empty to an exact ready owned queue;
// an error is never a request to wait. Prepared/Apply remain strict and fresh.
func nfqwsScopedAfterStartCurrent(ctx context.Context, b *NFQWSScopedBinding, p *NFQWSScopedPlan, current func(context.Context, *NFQWSScopedPlan) error) (bool, error) {
	if ctx == nil || b == nil || p == nil || current == nil || (b.queueReadiness == nil && b.network == nil) {
		return false, ErrNFQWSScopedOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return false, ErrNFQWSScopedOwner
	}
	if _, _, err := b.prepare(p, false); err != nil {
		return false, err
	}
	if err := current(ctx, p); err != nil {
		return false, fmt.Errorf("opening current: %w", err)
	}
	proof, err := b.ProcessRunning(ctx, p)
	if err != nil {
		return false, fmt.Errorf("running process readback: %w", err)
	}
	if err := nfqwsScopedProcessProof(p, proof, false); err != nil {
		return false, fmt.Errorf("running proof shape: %w", err)
	}
	if err := current(ctx, p); err != nil {
		return false, fmt.Errorf("current after process readback: %w", err)
	}
	openingReady, err := b.checkQueueReadiness(ctx, p, &proof.Child)
	if err != nil {
		return false, fmt.Errorf("opening queue readiness: %w", err)
	}
	if err := b.VerifyLAN(ctx, CloneLANPolicyRuntime(p.lan)); err != nil {
		return false, fmt.Errorf("opening LAN readback: %w", err)
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return false, fmt.Errorf("all-capture readback: %w", err)
	}
	if _, err := b.ruleCountsImage(p, rules, nfqwsScopedBeforeStart); err != nil {
		return false, fmt.Errorf("absent capture shape: %w", err)
	}
	if err := b.VerifyLAN(ctx, CloneLANPolicyRuntime(p.lan)); err != nil {
		return false, fmt.Errorf("closing LAN readback: %w", err)
	}
	closingReady, err := b.checkQueueReadiness(ctx, p, &proof.Child)
	if err != nil {
		return false, fmt.Errorf("closing queue readiness: %w", err)
	}
	if openingReady && !closingReady {
		return false, fmt.Errorf("owned queue disappeared: %w", ErrNFQWSScopedOwner)
	}
	after, err := b.ProcessRunning(ctx, p)
	if err != nil {
		return false, fmt.Errorf("closing running process readback: %w", err)
	}
	if proof != after || nfqwsScopedProcessProof(p, after, false) != nil {
		return false, fmt.Errorf("closing running proof shape: %w", ErrNFQWSScopedOwner)
	}
	if err := current(ctx, p); err != nil {
		return false, fmt.Errorf("closing current: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("closing context: %w", err)
	}
	return closingReady, nil
}

type nfqwsScopedQueueReadinessObserver struct {
	identity      func() error
	read          func(context.Context) ([]nfqwsScopedQueue, error)
	owner         func(context.Context, nfqwsScopedQueue) (string, error)
	stock         *nfqwsScopedStockQueueProof
	foreignSocket func(context.Context, nfqwsScopedQueue) (string, error)
}

type nfqwsScopedForeignQueueState struct {
	queue nfqwsScopedQueue
	inode string
}

type nfqwsScopedQueueReadinessState struct {
	ready   bool
	queue   nfqwsScopedQueue
	inode   string
	foreign []nfqwsScopedForeignQueueState
}

func (s nfqwsScopedQueueReadinessState) sameOwn(other nfqwsScopedQueueReadinessState) bool {
	return s.ready == other.ready && s.queue == other.queue && s.inode == other.inode
}

// Validate every observed inventory before sampling again: a foreign queue
// that subsequently disappears must never be mistaken for initial absence.
func nfqwsScopedQueueReadinessObserve(ctx context.Context, queue uint16, o nfqwsScopedQueueReadinessObserver) (bool, error) {
	if ctx == nil || queue == 0 || o.identity == nil || o.read == nil || o.owner == nil || o.stock != nil && (!o.stock.used.Load() || o.stock.queue != queue || o.foreignSocket == nil) {
		return false, ErrNFQWSScopedOwner
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := o.identity(); err != nil {
		return false, err
	}
	read := func() (nfqwsScopedQueueReadinessState, error) {
		if err := ctx.Err(); err != nil {
			return nfqwsScopedQueueReadinessState{}, err
		}
		queues, err := o.read(ctx)
		if err != nil {
			return nfqwsScopedQueueReadinessState{}, err
		}
		state := nfqwsScopedQueueReadinessState{}
		seen := map[uint16]bool{}
		for _, q := range queues {
			if seen[q.number] {
				return state, ErrNFQWSScopedOwner
			}
			seen[q.number] = true
			if q.number != queue {
				if !o.stock.contains(q.number) {
					return state, ErrNFQWSScopedOwner
				}
				inode, err := o.foreignSocket(ctx, q)
				if err != nil || inode == "" {
					return state, errors.Join(ErrNFQWSScopedOwner, err)
				}
				state.foreign = append(state.foreign, nfqwsScopedForeignQueueState{queue: q, inode: inode})
				continue
			}
			if q.copyMode != 2 || q.copyRange < 65531 {
				return state, ErrNFQWSScopedOwner
			}
			inode, err := o.owner(ctx, q)
			if err != nil || inode == "" {
				return state, errors.Join(ErrNFQWSScopedOwner, err)
			}
			state.ready, state.queue, state.inode = true, q, inode
		}
		slices.SortFunc(state.foreign, func(a, b nfqwsScopedForeignQueueState) int { return int(a.queue.number) - int(b.queue.number) })
		return state, nil
	}
	before, err := read()
	if err != nil {
		return false, err
	}
	after, err := read()
	if err != nil {
		return false, err
	}
	if !slices.Equal(before.foreign, after.foreign) || before.ready && !before.sameOwn(after) {
		return false, ErrNFQWSScopedOwner
	}
	if !before.ready && after.ready {
		// The newly observed occupant needs its own stable inventory/socket
		// bracket. This is a positive transition proof, not retry on error.
		closing, err := read()
		if err != nil || !closing.sameOwn(after) || !slices.Equal(closing.foreign, after.foreign) {
			return false, errors.Join(ErrNFQWSScopedOwner, err)
		}
	}
	if err := o.identity(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return after.ready, nil
}

// Concrete Linux reader for the private phase. Ready false proves a stable
// empty whole namespace; ready true binds the sole configured reservation to
// the exact child's open NETLINK_NETFILTER socket. All unknown states refuse.
func nfqwsScopedQueueReadiness(ctx context.Context, namespace string, queue uint16, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if runtime.GOOS != "linux" || ctx == nil || !nfqwsScopedNamespace(namespace) || queue == 0 || child == nil || child.PID <= 1 {
		return false, ErrNFQWSScopedOwner
	}
	identity := *child
	o := nfqwsScopedQueueReadinessObserver{
		identity: func() error {
			selfNS, err := os.Readlink("/proc/self/ns/net")
			actual, identityErr := components.ReadNFQWSRuntimeProcessIdentity(identity.PID)
			childNS, namespaceErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", identity.PID))
			if err != nil || identityErr != nil || namespaceErr != nil || selfNS != namespace || childNS != namespace || actual != identity {
				return errors.Join(ErrNFQWSScopedOwner, err, identityErr, namespaceErr)
			}
			return ctx.Err()
		},
		read: func(c context.Context) ([]nfqwsScopedQueue, error) {
			text, err := nfqwsScopedReadProc(c, "/proc/net/netfilter/nfnetlink_queue")
			if err != nil {
				return nil, err
			}
			return nfqwsScopedQueues(text)
		},
		owner: func(c context.Context, q nfqwsScopedQueue) (string, error) {
			text, err := nfqwsScopedReadProc(c, "/proc/net/netlink")
			if err != nil {
				return "", err
			}
			inode, err := nfqwsScopedSocketInode(text, q.portID)
			if err != nil {
				return "", err
			}
			dir := fmt.Sprintf("/proc/%d/fd", identity.PID)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) > 4096 {
				return "", errors.Join(ErrNFQWSScopedOwner, err)
			}
			found := false
			for _, entry := range entries {
				link, err := os.Readlink(filepath.Join(dir, entry.Name()))
				if err != nil {
					return "", errors.Join(ErrNFQWSScopedOwner, err)
				}
				found = found || link == "socket:["+inode+"]"
			}
			if !found {
				return "", ErrNFQWSScopedOwner
			}
			text, err = nfqwsScopedReadProc(c, "/proc/net/netlink")
			if err != nil {
				return "", err
			}
			after, err := nfqwsScopedSocketInode(text, q.portID)
			if err != nil || after != inode {
				return "", errors.Join(ErrNFQWSScopedOwner, err)
			}
			return inode, c.Err()
		},
	}
	return nfqwsScopedQueueReadinessObserve(ctx, queue, o)
}
