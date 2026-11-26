//go:build !linux

package dataplane

import "context"

func (*MihomoProbeAdapter) prepareLive(context.Context, Plan, string) (*mihomoLiveResource, error) {
	return nil, errMihomoLiveMaterial
}
func (*mihomoLiveResource) engineImage(context.Context) ([]byte, error) {
	return nil, errMihomoLiveMaterial
}
