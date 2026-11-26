//go:build !linux

package dataplane

import "context"

func waitMihomoSameBootSidecarExit(context.Context, *mihomoSameBootSidecar, *mihomoSameBootStatic) error {
	return ErrMihomoLiveRetirement
}
