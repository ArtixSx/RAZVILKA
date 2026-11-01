//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func observeMihomoProbeInactive(ctx context.Context, provider *netidentity.Provider) error {
	if xraySelectedTCPFinite(ctx) != nil || provider == nil {
		return ErrRuntimeInactivity
	}
	// The comparison pins are compiled release facts, not an installed receipt
	// or caller supplied process exemption. Renamed copies remain recognizable.
	images := components.ReviewedMihomoRuntimeImages()
	if len(images) == 0 {
		return ErrRuntimeInactivity
	}
	return provider.WithCurrent(ctx, func(held context.Context, identity netidentity.Identity) error {
		physical := netidentity.NewProcProvider()
		return physical.WithCurrent(held, func(observed context.Context, actual netidentity.Identity) error {
			if actual != identity {
				return ErrRuntimeInactivity
			}
			proof, err := scopedDNSInactivePlatformProof()
			if err != nil {
				return err
			}
			selfHash, selfInfo, err := mihomoColdFileHash(observed, "/proc/self/exe")
			if err != nil {
				return err
			}
			originalSame := proof.sameExecutable
			proof.sameExecutable = func(first, second string) (bool, error) {
				same, err := originalSame(first, second)
				if err != nil || same {
					return same, err
				}
				name, err := os.Readlink(second)
				if err != nil {
					return false, err
				}
				if strings.EqualFold(filepath.Base(strings.TrimSuffix(name, " (deleted)")), "mihomo") {
					return true, nil
				}
				info, err := os.Stat(second)
				if err != nil {
					return false, err
				}
				possible := info.Size() == selfInfo.Size()
				for _, image := range images {
					possible = possible || info.Size() == image.Size
				}
				if !possible {
					return false, nil
				}
				hash, _, err := mihomoColdFileHash(observed, second)
				if err != nil {
					return false, err
				}
				if hash == selfHash {
					return true, nil
				}
				for _, image := range images {
					if hash == image.SHA256 {
						return true, nil
					}
				}
				return false, nil
			}
			// Full original process/argv/birth/namespace and socket-table parsers.
			// There is no installer/parent exemption. This adapter owns no fixed
			// port while idle; a future source independently verifies its port.
			for range 2 {
				if err := scopedDNSInactiveProc(observed, proof, filepath.Join(installpath.State, "dataplane", "mihomo"), filepath.Join(installpath.Config, "config.json"), nil); err != nil {
					return err
				}
			}
			closingHash, closingInfo, err := mihomoColdFileHash(observed, "/proc/self/exe")
			if err != nil || closingHash != selfHash || !os.SameFile(selfInfo, closingInfo) || selfInfo.Size() != closingInfo.Size() {
				return errors.Join(ErrRuntimeInactivity, err)
			}
			return observed.Err()
		})
	})
}
