//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

type nfqwsPreAddMeasurement struct{}

func (*nfqwsPreAddMeasurement) sequence(ctx context.Context, s *policyEffectSession, runtime PolicyEffectRuntime, index int) error {
	return s.observeBeforeAddUnshared(ctx, runtime, index)
}

func (*nfqwsPreAddMeasurement) closed(int, error) {}
