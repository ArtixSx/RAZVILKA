//go:build linux

package dataplane

import (
	"context"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

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
				data, err := proc.read(held, proc.child, name, 32<<20)
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
