//go:build !linux || !razvilka_native_fixture

package dataplane

func mihomoSameBootNativeTiming(*mihomoSameBootRetirementCursor, string) func() { return func() {} }
func mihomoSameBootNativeOwnerTiming(*mihomoSameBootCleanup, string) func()     { return func() {} }
