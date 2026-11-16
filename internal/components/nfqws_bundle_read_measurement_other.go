//go:build !linux || (!amd64 && !arm64) || !razvilka_native_fixture

package components

func noteManagedNFQWSPayloadRead(*Manager, int64) {}
func noteManagedNFQWSRuntimeFrame(*Manager, int)  {}
