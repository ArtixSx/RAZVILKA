//go:build linux && razvilka_native_fixture

package components

import (
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// InstallMihomoPredecessorNativeFixture exists only in the native fixture
// build. It feeds the reviewed previous official asset through the original
// immutable installer on an absent target. It grants no runtime exemptions.
func (m *Manager) InstallMihomoPredecessorNativeFixture(ctx context.Context, compressed []byte, guard, rename func(context.Context, func() error) error) (Result, error) {
	if m == nil || ctx == nil || guard == nil || rename == nil || len(compressed) != 22846526 || digest(compressed) != "8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10" {
		return Result{}, ErrRecoveryAuthority
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.fencePackageMutation()
	if err != nil {
		return Result{}, err
	}
	defer release()
	_, _, _, paths, err := m.mihomoReleaseLayout()
	if err != nil {
		return Result{}, err
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return Result{}, restorejournal.ErrConflict
		}
	}
	var image restorejournal.Image
	err = guard(ctx, func() error {
		var e error
		image, e = m.stageMihomoArtifact(ctx, compressed, "8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10", rename)
		return e
	})
	if err != nil {
		return Result{}, err
	}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil || ref.SHA256 != "3122d100e8177501776109f1a6253a694611627cf4d7c7ec82705855cf8626a8" || ref.Size != 61993086 {
		return Result{}, ErrRecoveryAuthority
	}
	return m.installMihomoImage(ctx, releaseInfo{Version: "1.19.32"}, image, guard, rename)
}
