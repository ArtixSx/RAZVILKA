//go:build !linux || !razvilka_native_fixture

package dataplane

func mihomoLiveClosingFixtureFaultLocked(*mihomoLiveResource) func(int) error { return nil }
