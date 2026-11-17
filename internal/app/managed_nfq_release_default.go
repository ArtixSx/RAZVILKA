//go:build !linux || (!amd64 && !arm64) || !razvilka_native_fixture

package app

func managedNFQExperimentalRuntime(*ManagedNFQWSListRuntime) bool { return false }
