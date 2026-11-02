//go:build !linux

package dataplane

import "context"

func (r *mihomoLiveResource) canaryLive(context.Context) error { return errMihomoLiveMaterial }
