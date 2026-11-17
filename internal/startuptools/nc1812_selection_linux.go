//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func acquireNC1812Selected(lifetime context.Context, provider *netidentity.Provider, set nc1812ToolSet) (*Lease, error) {
	if lifetime == nil || lifetime.Err() != nil || provider == nil || os.Geteuid() != 0 || runtime.GOARCH != "arm64" || set > nc1812AmneziaWGTools {
		return nil, at("ACQUIRE_PLATFORM", nil)
	}
	hint, cancel := acquisitionContext(lifetime, time.Time{})
	defer cancel()
	deadline, _ := hint.Deadline()
	digest, err := readNC1812MainHint(hint)
	if err != nil {
		return nil, err
	}
	p, err := nc1812ProfileForHint(digest, set)
	if err != nil || hint.Err() != nil {
		return nil, errors.Join(err, hint.Err())
	}
	// The hint's files are already closed. Pass the ORIGINAL lifetime, not
	// hint; only its absolute acquisition deadline crosses this boundary.
	if p.wgEngine != "" {
		return acquireWGWithDeadline(lifetime, provider, p, deadline)
	}
	return acquireWithDeadline(lifetime, provider, p, deadline)
}

func readNC1812MainHint(ctx context.Context) (digest string, resultErr error) {
	if ctx == nil || ctx.Err() != nil {
		return "", at("NC1812_SELECTION_CONTEXT", nil)
	}
	r := &heldReview{nodes: map[string]heldNode{}}
	canonical, err := r.resolve("/opt/sbin/xtables-multi")
	if err != nil {
		return "", at("NC1812_SELECTION_PATH", err)
	}
	before := r.nodes[canonical].info
	if !before.Mode().IsRegular() || before.Mode().Perm()&0100 == 0 || before.Size() <= 0 || before.Size() > maxImageBytes {
		return "", at("NC1812_SELECTION_BOUNDS", nil)
	}
	fd, err := syscall.Open(canonical, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", at("NC1812_SELECTION_OPEN", err)
	}
	file := os.NewFile(uintptr(fd), canonical)
	defer func() {
		resultErr = errors.Join(resultErr, file.Close(), ctx.Err())
		if resultErr != nil {
			digest = ""
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameNode(before, opened) {
		return "", at("NC1812_SELECTION_OPEN_CHANGED", err)
	}
	hash, hashErr := hashImage(ctx, file, opened.Size())
	after, statErr := file.Stat()
	named, pathErr := os.Lstat(canonical)
	pathsErr := r.pathsCurrent(ctx)
	if hashErr != nil || statErr != nil || pathErr != nil || pathsErr != nil || !sameNode(opened, after) || !sameNode(after, named) {
		return "", at("NC1812_SELECTION_CHANGED", errors.Join(hashErr, statErr, pathErr, pathsErr))
	}
	return hex.EncodeToString(hash[:]), nil
}
