//go:build !linux || !razvilka_native_fixture

package startuptools

func domainNativeToolStarted(string) {}

func domainNativeGateWait(*Lease) func(string) { return func(string) {} }
func domainNativeGateReleased(*Lease)          {}
