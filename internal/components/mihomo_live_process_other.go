//go:build !linux

package components

import "context"

func newMihomoLiveNative(context.Context, *MihomoLiveProcess) (mihomoLiveNative, error) {
	return nil, ErrMihomoLiveOwner
}
