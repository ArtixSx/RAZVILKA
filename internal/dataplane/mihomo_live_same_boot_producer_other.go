//go:build !linux || !razvilka_native_fixture

package dataplane

import "context"

func mihomoSameBootNativeProducerPolicyACK(context.Context, *mihomoLiveResource, string) error {
	return nil
}

func installMihomoSameBootNativeACKCut(context.Context, *mihomoSameBootRetirementCursor) error {
	return nil
}

func mihomoSameBootNativeStage(context.Context, *mihomoSameBootRetirementCursor, string, func() error) error {
	return nil
}
