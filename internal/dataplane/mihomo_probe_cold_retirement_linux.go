//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func mihomoColdFileHash(ctx context.Context, path string) (string, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 128<<20 {
		return "", nil, ErrMihomoProbeRetirement
	}
	h := sha256.New()
	buf := make([]byte, 256<<10)
	for offset := int64(0); offset < before.Size(); {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		want := int(min(int64(len(buf)), before.Size()-offset))
		n, e := file.ReadAt(buf[:want], offset)
		if n != want || e != nil {
			return "", nil, ErrMihomoProbeRetirement
		}
		h.Write(buf[:n])
		offset += int64(n)
	}
	var tail [1]byte
	if n, err := file.ReadAt(tail[:], before.Size()); n != 0 || !errors.Is(err, io.EOF) {
		return "", nil, ErrMihomoProbeRetirement
	}
	after, err := file.Stat()
	named, namedErr := os.Stat(path)
	if err != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", nil, ErrMihomoProbeRetirement
	}
	return hex.EncodeToString(h.Sum(nil)), after, ctx.Err()
}

func observeMihomoColdAbsence(ctx context.Context, provider *netidentity.Provider, d ExecutionMihomoProbeDefinition, stateRoot string) (result netidentity.Identity, resultErr error) {
	if xraySelectedTCPFinite(ctx) != nil || provider == nil || d.Source.ParentOrigin.Validate() != nil || d.Source.ParentOrigin.BootID != d.NetworkIdentity.BootID {
		return result, ErrMihomoProbeRetirement
	}
	err := provider.WithCurrent(ctx, func(held context.Context, current netidentity.Identity) error {
		if current != d.NetworkIdentity {
			return ErrMihomoProbeRetirement
		}
		parent := d.Source.ParentOrigin
		if err := components.ObserveMihomoProbeParentGone(held, parent); err != nil {
			return err
		}
		// Reuse the existing complete controller/process/socket parser, including
		// PID birth, mutable argv, executable and source namespace bookends. A
		// copied/renamed controller or Mihomo image also refuses by exact bytes.
		proof, err := scopedDNSInactivePlatformProof()
		if err != nil {
			return err
		}
		selfHash, selfInfo, err := mihomoColdFileHash(held, "/proc/self/exe")
		if err != nil {
			return err
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
			if info.Size() != selfInfo.Size() && info.Size() != parent.ExecutableSize && info.Size() != d.Source.BinarySize {
				return false, nil
			}
			hash, _, err := mihomoColdFileHash(held, second)
			if err != nil {
				return false, err
			}
			return hash == selfHash || hash == parent.ExecutableSHA256 || hash == d.Source.BinarySHA256, nil
		}
		for range 2 {
			if err := components.ObserveMihomoProbeParentGone(held, parent); err != nil {
				return err
			}
			if err := scopedDNSInactiveProc(held, proof, filepath.Join(stateRoot, scopedDNSAdapterID), "/opt/etc/razvilka/config.json", map[uint16]bool{uint16(d.Source.SOCKSPort): true}); err != nil {
				return err
			}
			if err := observeMihomoProbeListenerAbsent(held, provider, current, d.Source.SOCKSPort); err != nil {
				return err
			}
		}
		if err := components.ObserveMihomoProbeParentGone(held, parent); err != nil {
			return err
		}
		closingHash, closingInfo, err := mihomoColdFileHash(held, "/proc/self/exe")
		if err != nil || closingHash != selfHash || !os.SameFile(selfInfo, closingInfo) || selfInfo.Size() != closingInfo.Size() {
			return ErrMihomoProbeRetirement
		}
		result = current
		return nil
	})
	if err != nil {
		return netidentity.Identity{}, errors.Join(err, ErrMihomoProbeRetirement)
	}
	return result, nil
}
