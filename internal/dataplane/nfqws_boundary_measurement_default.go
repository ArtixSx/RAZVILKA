//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

// Ordinary builds perform no diagnostic clocks, context reads, logging or environment lookup.
type nfqwsBoundaryMeasurement struct{}

func beginNFQWSBoundaryMeasurement(context.Context, string, string) nfqwsBoundaryMeasurement {
	return nfqwsBoundaryMeasurement{}
}
func (*nfqwsBoundaryMeasurement) begin(string)                        {}
func (*nfqwsBoundaryMeasurement) cause(string)                        {}
func (*nfqwsBoundaryMeasurement) finish(context.Context, error, bool) {}
