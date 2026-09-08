//go:build !linux

package systemprobe

import "context"

func newPlatformEpochSource(context.Context) (epochSource, error) {
	return nil, ErrNetworkUnavailable
}
