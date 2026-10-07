//go:build !linux

package nativeowner

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

type unavailable struct{}

func nativePlatform() platform { return unavailable{} }
func (unavailable) acquire(context.Context, nativeaccept.Acquisition, HelperAsset) (scopeFacts, error) {
	return nil, ErrOwned
}
func RunSupervisor() int { return 125 }
