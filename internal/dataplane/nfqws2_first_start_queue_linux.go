//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// nfqws2FirstStartQueueObserve reads the owned queue binding twice inside
// the original provider's same-thread bracket. Each frame re-reads the exact
// process receipt and its network namespace around the queue, socket and
// descriptor reads; both frames must agree. Nothing is signalled or adopted.
func nfqws2FirstStartQueueObserve(ctx context.Context, a *NFQWS2Adapter, s *NFQWSRuntimeInactiveSource, queue uint16, receipt components.NFQWSRuntimeProcessIdentity) (nfqws2FirstStartQueue, error) {
	var none, bound nfqws2FirstStartQueue
	if a == nil || !nfqws2InactiveFinite(ctx) || s == nil || s.self != s || s.adapter != a || s.provider == nil || s.platform.queues == nil || s.platform.sockets == nil ||
		s.platform.readlink == nil || s.platform.procRoot == "" || queue == 0 || receipt.PID <= 1 || receipt.PID == s.platform.selfPID || receipt.BootID != s.identity.BootID {
		return none, errNFQWS2FirstStartQueue
	}
	uses := 0
	err := s.provider.WithCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
		uses++
		if uses != 1 || !nfqws2InactiveFinite(c) || id != s.identity {
			return errNFQWS2FirstStartQueue
		}
		process := func() error {
			if err := s.current(c); err != nil {
				return err
			}
			actual, err := a.readFirstStartProcess(receipt.PID)
			if err != nil || actual != receipt {
				return errors.Join(errNFQWS2FirstStartQueue, err)
			}
			if id.Kind == netidentity.ProcNetInode {
				namespace, err := s.platform.readlink(filepath.Join(s.platform.procRoot, strconv.Itoa(receipt.PID), "ns", "net"))
				if err != nil || namespace != fmt.Sprintf("net:[%d]", id.Inode) {
					return errors.Join(errNFQWS2FirstStartQueue, err)
				}
			}
			return c.Err()
		}
		frame := func() (nfqws2FirstStartQueue, error) {
			if err := process(); err != nil {
				return none, err
			}
			queues, err := s.platform.queues(c)
			if err != nil {
				return none, errors.Join(errNFQWS2FirstStartQueue, err)
			}
			sockets, err := s.platform.sockets(c)
			if err != nil {
				return none, errors.Join(errNFQWS2FirstStartQueue, err)
			}
			descriptors, err := nfqws2FirstStartDescriptors(c, s.platform, receipt.PID)
			if err != nil {
				return none, err
			}
			current, err := nfqws2FirstStartQueueBound(queues, sockets, descriptors, queue)
			if err != nil {
				return none, err
			}
			// The port may be rebound while descriptors are read; the same
			// port must still name the same socket afterwards.
			closing, err := s.platform.sockets(c)
			if err != nil {
				return none, errors.Join(errNFQWS2FirstStartQueue, err)
			}
			inode, err := nfqwsScopedSocketInode(closing, current.PortID)
			if err != nil || inode != current.Inode {
				return none, errors.Join(errNFQWS2FirstStartQueue, err)
			}
			return current, process()
		}
		first, err := frame()
		if err != nil {
			return err
		}
		second, err := frame()
		if err != nil {
			return err
		}
		if first != second {
			return errNFQWS2FirstStartQueue
		}
		bound = first
		return nil
	})
	if err != nil || uses != 1 || ctx.Err() != nil {
		return none, errors.Join(errNFQWS2FirstStartQueue, err, ctx.Err())
	}
	return bound, nil
}

// Only socket link targets are kept. A descriptor closed during the scan is
// an unknown frame, never a missing socket.
func nfqws2FirstStartDescriptors(ctx context.Context, platform nfqws2InactivePlatform, pid int) ([]string, error) {
	dir := filepath.Join(platform.procRoot, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 4096 {
		return nil, errors.Join(errNFQWS2FirstStartQueue, err)
	}
	var sockets []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		link, err := platform.readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, errors.Join(errNFQWS2FirstStartQueue, err)
		}
		if strings.HasPrefix(link, "socket:[") {
			sockets = append(sockets, link)
		}
	}
	return sockets, nil
}
