//go:build !linux || !razvilka_native_fixture

package dataplane

// Ordinary builds have no clocks, environment lookup, output, or retained state.
type wgRuntimeInactiveMeasurement struct{}

func beginWGRuntimeInactiveMeasurement() wgRuntimeInactiveMeasurement {
	return wgRuntimeInactiveMeasurement{}
}
func (*wgRuntimeInactiveMeasurement) begin(int, string, int, int) {}
func (*wgRuntimeInactiveMeasurement) end(error, bool)             {}
func (*wgRuntimeInactiveMeasurement) finish(error, bool)          {}
