//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Actual complete process/socket inventory, including renamed copies of both
// runtime images. Same-boot recovery additionally proves the original parent
// gone in its exact proc/PID namespace. New-boot absence is freshly observed;
// neither a reboot nor a receipt alone grants metadata retirement.
func observeMihomoLiveColdProcesses(ctx context.Context, provider *netidentity.Provider, d ExecutionMihomoLiveDefinition, stateRoot string) (result netidentity.Identity, resultErr error) {
	if xraySelectedTCPFinite(ctx) != nil || provider == nil || d.validate() != nil || d.Source.ParentOrigin.Validate() != nil || d.Source.ParentOrigin.BootID != d.NetworkIdentity.BootID {
		return result, mihomoSameBootNativeFailure(ctx, "process-owner", ErrMihomoProbeRetirement)
	}
	err := provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		sameBoot := current.BootID == d.NetworkIdentity.BootID
		if sameBoot && current != d.NetworkIdentity {
			return mihomoSameBootNativeFailure(held, "process-network", ErrMihomoProbeRetirement)
		}
		parent := d.Source.ParentOrigin
		if err := func() error {
			if sameBoot {
				return components.ObserveMihomoProbeParentGone(held, parent)
			}
			return nil
		}(); err != nil {
			return mihomoSameBootNativeFailure(held, "process-parent-opening", err)
		}
		// Reuse the existing complete controller/process/socket parser, including
		// PID birth, mutable argv, executable and source namespace bookends. A
		// copied/renamed controller or Mihomo image also refuses by exact bytes.
		proof, err := scopedDNSInactivePlatformProof()
		if err != nil {
			return mihomoSameBootNativeFailure(held, "process-platform", err)
		}
		// Same-host full parent ABBA showed the large byte image timing out
		// under race instrumentation. Use the existing two-fresh-SHA path in
		// every build here: normal is modestly slower, both race samples finish.
		// All process/socket and opening/closing metadata observations remain.
		image, err := borrowMihomoColdSelfImage(held, "/proc/self/exe", nil)
		if err != nil {
			return mihomoSameBootNativeFailure(held, "process-self-opening", err)
		}
		if image != nil {
			defer image.release()
		}
		readSelf := func() (string, os.FileInfo, error) {
			if image != nil {
				return image.read(held)
			}
			defer mihomoSameBootMeasureContext(held, "source-self-sha")()
			return mihomoColdFileHash(held, "/proc/self/exe")
		}
		selfHash, selfInfo, err := readSelf()
		if err != nil {
			return mihomoSameBootNativeFailure(held, "process-self-opening", err)
		}
		originalSame := proof.sameExecutable
		proof.sameExecutable = func(first, second string) (bool, error) {
			same, err := originalSame(first, second)
			if err != nil || same {
				return same, err
			}
			info, err := os.Stat(second)
			if err != nil {
				return false, err
			}
			if info.Size() != selfInfo.Size() && info.Size() != parent.ExecutableSize && info.Size() != d.Source.BinarySize && info.Size() != d.Sidecar.BinarySize {
				return false, nil
			}
			hash, _, err := mihomoColdFileHash(held, second)
			if err != nil {
				return false, err
			}
			return hash == selfHash || hash == parent.ExecutableSHA256 || hash == d.Source.BinarySHA256 || hash == d.Sidecar.BinarySHA256, nil
		}
		for range 2 {
			if err := func() error {
				if sameBoot {
					return components.ObserveMihomoProbeParentGone(held, parent)
				}
				return nil
			}(); err != nil {
				return mihomoSameBootNativeFailure(held, "process-parent-pass", err)
			}
			if err := scopedDNSInactiveProc(held, proof, filepath.Join(stateRoot, scopedDNSAdapterID), "/opt/etc/razvilka/config.json", map[uint16]bool{uint16(d.Profile.SOCKSPort): true}); err != nil {
				return mihomoSameBootNativeProcFailure(held, err)
			}
			if err := observeMihomoProbeListenerAbsent(held, provider, current, d.Profile.SOCKSPort); err != nil {
				return mihomoSameBootNativeFailure(held, "process-listener", err)
			}
		}
		if err := func() error {
			if sameBoot {
				return components.ObserveMihomoProbeParentGone(held, parent)
			}
			return nil
		}(); err != nil {
			return mihomoSameBootNativeFailure(held, "process-parent-closing", err)
		}
		closingHash, closingInfo, err := readSelf()
		if err != nil || closingHash != selfHash || !os.SameFile(selfInfo, closingInfo) || selfInfo.Size() != closingInfo.Size() {
			return mihomoSameBootNativeFailure(held, "process-self-closing", ErrMihomoProbeRetirement)
		}
		result = current
		return nil
	})
	if err != nil {
		return netidentity.Identity{}, mihomoSameBootNativeFailure(ctx, "process-provider", errors.Join(err, ErrMihomoProbeRetirement))
	}
	return result, nil
}
