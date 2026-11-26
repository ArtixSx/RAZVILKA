//go:build linux && amd64 && razvilka_native_fixture

package components

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"os"
)

// InstallHEVPredecessorNativeFixture admits only the exact original official
// ELF onto absent fixture targets. It is absent from all ordinary builds.
func (m *Manager) InstallHEVPredecessorNativeFixture(ctx context.Context, binary []byte, guard, rename func(context.Context, func() error) error) (Result, error) {
	if m == nil || ctx == nil || guard == nil || rename == nil || len(binary) != 411528 || digest(binary) != "a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03" {
		return Result{}, ErrRecoveryAuthority
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.fencePackageMutation()
	if err != nil {
		return Result{}, err
	}
	defer release()
	if err := m.checkHEVReleaseIdle(ctx); err != nil {
		return Result{}, err
	}
	_, _, paths, err := m.hevReleaseLayout()
	if err != nil {
		return Result{}, err
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return Result{}, restorejournal.ErrConflict
		}
	}
	spec, _ := lookup("hev-socks5-tunnel")
	return m.installHEVImageGuarded(ctx, spec, releaseInfo{Version: "2.17.1"}, binary, guard, rename)
}
