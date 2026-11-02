//go:build !linux || (!amd64 && !arm64) || !razvilka_native_fixture

package dataplane

import "context"

func measureNFQWSProbePhase(*nfqwsProbeExecution, nfqwsProbeMeasuredPhase) func()   { return func() {} }
func measureNFQWSProbeContextPhase(context.Context, nfqwsProbeMeasuredPhase) func() { return func() {} }
