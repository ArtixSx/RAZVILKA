//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package app

// Only the existing nonshipping, original private physical fixture may keep
// exercising experimental positive flows. Tags alone do not enable a runtime.
func managedNFQExperimentalRuntime(r *ManagedNFQWSListRuntime) bool {
	if r == nil || !r.original() {
		return false
	}
	s, ok := r.physicalSource.(*nativeFixtureNFQListPhysicalSource)
	return ok && s.original(r)
}
