//go:build !linux || (!amd64 && !arm64) || !razvilka_native_fixture

package dataplane

func noteNFQInventoryRead(int) {}
