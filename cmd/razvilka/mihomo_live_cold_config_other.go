//go:build !linux

package main

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type mihomoLiveColdConfiguration struct{}

func openMihomoLiveColdConfiguration(context.Context, string) (*mihomoLiveColdConfiguration, error) {
	return nil, dataplane.ErrMihomoLiveRetirement
}
func (*mihomoLiveColdConfiguration) Current(context.Context) error {
	return dataplane.ErrMihomoLiveRetirement
}
func (*mihomoLiveColdConfiguration) Close() error { return nil }
