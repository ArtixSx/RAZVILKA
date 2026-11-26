//go:build linux

package dataplane

import (
	"context"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Only these actual rooted proc aliases use the whole conntrack-table bound.
// Other process/socket reads retain their independent smaller limits.
func (r *xraySelectedTCPProc) readConntrack(ctx context.Context, name string) ([]byte, error) {
	if name != "net/nf_conntrack" && name != "net/ip_conntrack" {
		return nil, errXraySelectedTCPRuntime
	}
	fd, err := r.open(ctx, r.child, name, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	data, err := xraySelectedTCPReadConntrackFD(ctx, fd)
	if err != nil || !r.procFile(fd, unix.S_IFREG) || !r.sameMount(ctx, fd) {
		return nil, errXraySelectedTCPRuntime
	}
	return data, nil
}

func xraySelectedTCPReadConntrackFD(ctx context.Context, fd int) ([]byte, error) {
	return xraySelectedTCPReadBoundedFD(ctx, fd, xraySelectedTCPConntrackLimit, xraySelectedTCPConntrackLimit)
}

func xraySelectedTCPObserveConntrackSettled(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, spec XraySelectedTCPRedirectSpec) error {
	if provider == nil || xraySelectedTCPFinite(ctx) != nil || expected.Validate() != nil {
		return errXraySelectedTCPRuntime
	}
	return provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != expected {
			return errXraySelectedTCPRuntime
		}
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		if err != nil {
			return err
		}
		defer proc.close()
		for pass := 0; pass < 2; pass++ {
			if proc.network(held, expected) != nil {
				return errXraySelectedTCPRuntime
			}
			directory, err := proc.open(held, proc.child, "net", true)
			if err != nil {
				return err
			}
			entries := os.NewFile(uintptr(directory), "[original conntrack directory]")
			names, listErr := entries.Readdirnames(513)
			extra, endErr := entries.Readdirnames(1)
			_ = entries.Close()
			if listErr != nil && listErr != io.EOF || len(names) > 512 || len(extra) != 0 || endErr != io.EOF {
				return errXraySelectedTCPRuntime
			}
			present := make(map[string]bool)
			for _, name := range names {
				if present[name] {
					return errXraySelectedTCPRuntime
				}
				present[name] = true
			}
			found := false
			for i, name := range []string{"net/nf_conntrack", "net/ip_conntrack"} {
				if !present[name[4:]] {
					continue
				}
				data, err := proc.readConntrack(held, name)
				if err != nil {
					return err
				}
				found = true
				if err := xraySelectedTCPConntrackSettled(data, i == 1, spec); err != nil {
					return err
				}
			}
			if !found || proc.network(held, expected) != nil || proc.current(held) != nil {
				return errXraySelectedTCPRuntime
			}
		}
		return held.Err()
	})
}
