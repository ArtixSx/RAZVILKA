//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

func domainTCPMeasurePureGuard(ctx context.Context, _ string) (context.Context, func()) {
	return ctx, func() {}
}
func domainTCPMeasureGuardRead(context.Context, string) {}
