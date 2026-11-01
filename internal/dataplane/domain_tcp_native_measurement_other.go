//go:build !linux || !razvilka_native_fixture

package dataplane

func domainTCPMeasure(string) func(int64) { return func(int64) {} }
