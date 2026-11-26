//go:build !linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func xraySelectedTCPObserveConntrackSettled(context.Context, *netidentity.Provider, netidentity.Identity, XraySelectedTCPRedirectSpec) error {
	return errXraySelectedTCPRuntime
}
