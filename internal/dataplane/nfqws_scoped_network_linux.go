//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// CheckTypedNFQWSScopedQueue uses the concrete provider's same-thread opening
// and closing observations. nil child requires positively empty whole queue
// inventory; a supplied child must own the sole exact configured ready queue.
// An identity or an absent namespace symlink never grants this observation.
func CheckTypedNFQWSScopedQueue(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, queue uint16, child *components.NFQWSRuntimeProcessIdentity) error {
	ready, err := nfqwsScopedTypedQueueObserve(ctx, provider, expected, queue, child)
	if err != nil || ready != (child != nil) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

func nfqwsScopedTypedQueueReadiness(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, queue uint16, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if child == nil {
		return false, ErrNFQWSScopedOwner
	}
	return nfqwsScopedTypedQueueObserve(ctx, provider, expected, queue, child)
}

func nfqwsScopedTypedQueueObserve(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, queue uint16, child *components.NFQWSRuntimeProcessIdentity) (bool, error) {
	if ctx == nil || provider == nil || expected.Validate() != nil || queue == 0 || child != nil && (child.PID <= 1 || child.BootID != expected.BootID) {
		return false, ErrNFQWSScopedOwner
	}
	var identity components.NFQWSRuntimeProcessIdentity
	if child != nil {
		identity = *child
	}
	ready := false
	err := provider.WithCurrent(ctx, func(c context.Context, current netidentity.Identity) error {
		if current != expected {
			return ErrNFQWSScopedOwner
		}
		o := nfqwsScopedQueueReadinessObserver{
			identity: func() error {
				if child == nil {
					return c.Err()
				}
				actual, err := components.ReadNFQWSRuntimeProcessIdentity(identity.PID)
				if err != nil || actual != identity {
					return errors.Join(ErrNFQWSScopedOwner, err)
				}
				if expected.Kind == netidentity.ProcNetInode {
					namespace, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", identity.PID))
					if err != nil || namespace != fmt.Sprintf("net:[%d]", expected.Inode) {
						return errors.Join(ErrNFQWSScopedOwner, err)
					}
				}
				// The explicit reviewed singleton provider freshly proves the
				// compiled single-init-net profile. No missing-link inference.
				return c.Err()
			},
			read: func(c context.Context) ([]nfqwsScopedQueue, error) {
				data, err := backendInventoryThreadProc(c, backendThreadQueues)
				if err != nil {
					return nil, errors.Join(ErrNFQWSScopedQueueInventory, err)
				}
				return nfqwsScopedQueues(string(data))
			},
			owner: func(c context.Context, queue nfqwsScopedQueue) (string, error) {
				if child == nil {
					return "", ErrNFQWSScopedOwner
				}
				data, err := backendInventoryThreadProc(c, backendThreadNetlink)
				if err != nil {
					return "", err
				}
				inode, err := nfqwsScopedSocketInode(string(data), queue.portID)
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
					if err := c.Err(); err != nil {
						return "", err
					}
					link, err := os.Readlink(filepath.Join(dir, entry.Name()))
					if err != nil {
						return "", errors.Join(ErrNFQWSScopedOwner, err)
					}
					found = found || link == "socket:["+inode+"]"
				}
				if !found {
					return "", ErrNFQWSScopedOwner
				}
				data, err = backendInventoryThreadProc(c, backendThreadNetlink)
				if err != nil {
					return "", err
				}
				after, err := nfqwsScopedSocketInode(string(data), queue.portID)
				if err != nil || after != inode {
					return "", errors.Join(ErrNFQWSScopedOwner, err)
				}
				return inode, c.Err()
			},
		}
		var err error
		ready, err = nfqwsScopedQueueReadinessObserve(c, queue, o)
		return err
	})
	if err != nil {
		return false, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return ready, nil
}
