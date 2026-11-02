//go:build !linux

package dataplane

import "context"

func stopMihomoSameBootSidecar(context.Context, *mihomoSameBootCleanup) error {
	return ErrMihomoLiveRetirement
}

func observeMihomoSameBootHome(context.Context, *mihomoSameBootCleanup) (mihomoColdHomeArchive, error) {
	return mihomoColdHomeArchive{}, ErrMihomoLiveRetirement
}
