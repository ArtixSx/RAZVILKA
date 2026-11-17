//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

func domainTCPMeasure(string) func(int64)                               { return func(int64) {} }
func domainTCPMeasureAcceptedStage(context.Context, string) func(error) { return func(error) {} }
func domainTCPMeasureForwardStage(context.Context, string, string) func(error) {
	return func(error) {}
}
