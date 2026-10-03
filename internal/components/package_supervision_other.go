//go:build !linux

package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func (execRunner) runSupervised(context.Context, string, []string, packageSupervision, *ownedfs.Root, string) ([]byte, error) {
	return nil, ErrUpdateUnknown
}
func supervisionInactive(context.Context, packageSupervision) error { return ErrUpdateUnknown }
func supervisionRootSafe(string) error                              { return ErrUpdateUnknown }
func ProbePackageSupervision() error                                { return ErrUpdateUnknown }
func RunPackageSupervisor(string, string, string) int               { return 1 }
