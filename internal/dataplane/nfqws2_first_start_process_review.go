package dataplane

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// reviewFirstStartProcess admits no new owner from a PID/DTO. It rechecks the
// original process receipt, the actual stock PID file and the original bound
// complete proc source before the caller can enter stock stop. Other NFQ
// processes, including zombies and alternate queue arguments, always refuse.
func (a *NFQWS2Adapter) reviewFirstStartProcess(ctx context.Context, receipt components.NFQWSRuntimeProcessIdentity) error {
	if a == nil || !nfqws2InactiveFinite(ctx) {
		return ErrNFQWSManagedProcessUnknown
	}
	if a.firstStartStopReview != nil {
		return a.firstStartStopReview(ctx, receipt)
	}
	s := a.inactivity
	if s == nil || s.self != s || s.adapter != a || s.provider == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return a.reviewFirstStartProcessWithSources(ctx, receipt, s.platform, s.provider.WithCurrent)
}

// Private source model seam: production only calls this with the original
// source's real platform/provider above, never with a presentation snapshot.
func (a *NFQWS2Adapter) reviewFirstStartProcessWithSources(ctx context.Context, receipt components.NFQWSRuntimeProcessIdentity, proof nfqws2InactivePlatform,
	withCurrent func(context.Context, func(context.Context, netidentity.Identity) error) error) error {
	if a == nil || !nfqws2InactiveFinite(ctx) || withCurrent == nil || proof.protected == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	s := a.inactivity
	if s == nil || s.self != s || s.adapter != a || s.current(ctx) != nil || receipt.PID <= 1 || receipt.PID == proof.selfPID || receipt.BootID != s.identity.BootID || receipt.Start == "" || !lanPolicyHash(receipt.ArgumentsSHA256) {
		return ErrNFQWSManagedProcessUnknown
	}
	program := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(a.InitPath))), "usr", "bin", "nfqws2")
	if receipt.Executable != program {
		return ErrNFQWSManagedProcessUnknown
	}
	pidPath := a.firstStartPIDPath()
	pidImage, exists, err := nfqws2Read(pidPath)
	if err != nil || !exists || len(pidImage) > 32 || strings.TrimSpace(string(pidImage)) != strconv.Itoa(receipt.PID) {
		return ErrNFQWSManagedProcessUnknown
	}
	current := func() error {
		if s.current(ctx) != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		parent, e := os.Lstat(filepath.Dir(pidPath))
		if e != nil || !proof.protected(parent, true, false) {
			return ErrNFQWSManagedProcessUnknown
		}
		info, e := os.Lstat(pidPath)
		if e != nil || !proof.protected(info, false, false) {
			return ErrNFQWSManagedProcessUnknown
		}
		actual, present, e := nfqws2Read(pidPath)
		if e != nil || !present || !bytes.Equal(actual, pidImage) {
			return ErrNFQWSManagedProcessUnknown
		}
		identity, e := a.readFirstStartProcess(receipt.PID)
		if e != nil || identity != receipt {
			return ErrNFQWSManagedProcessUnknown
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	uses := 0
	err = withCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
		uses++
		if uses != 1 || !nfqws2InactiveFinite(c) || id != s.identity || c.Err() != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		for pass := 0; pass < 2; pass++ {
			if err := current(); err != nil {
				return err
			}
			if err := nfqws2InactiveProcessesExcept(c, proof, a, receipt.PID, current); err != nil {
				return err
			}
		}
		return current()
	})
	if err != nil {
		return err
	}
	if uses != 1 {
		return ErrNFQWSManagedProcessUnknown
	}
	if err := nfqws2InactiveProcessesExcept(ctx, proof, a, receipt.PID, current); err != nil {
		return err
	}
	return current()
}
