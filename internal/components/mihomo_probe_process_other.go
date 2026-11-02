//go:build !linux

package components

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (s *MihomoProbeSource) RunProbe(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, observe func(context.Context, *MihomoProbeProcess) error) (*MihomoProbeProcess, error) {
	return nil, ErrMihomoProbePending
}

func (s *MihomoProbeSource) RunProbeAdmitted(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, admission func(context.Context, func() error) error, observe func(context.Context, *MihomoProbeProcess) error) (*MihomoProbeProcess, error) {
	return nil, ErrMihomoProbePending
}
