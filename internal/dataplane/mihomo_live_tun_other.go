//go:build !linux

package dataplane

import "context"

func (*mihomoLiveSidecar) tunInterfaceIndex(context.Context, bool) (int, error) {
	return 0, errMihomoLiveMaterial
}
