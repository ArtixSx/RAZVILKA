//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

func mihomoSameBootNativeTiming(*mihomoSameBootRetirementCursor, string) func() { return func() {} }
func mihomoSameBootNativeOwnerTiming(*mihomoSameBootCleanup, string) func()     { return func() {} }

func mihomoSameBootNativeFailure(_ context.Context, _ string, err error) error { return err }
