//go:build !linux || (!amd64 && !arm64)

package startuptools

import "context"

func (*Lease) runWGInactivity(context.Context, string, ...string) ([]byte, error) {
	return nil, at("WG_INACTIVITY_PLATFORM", nil)
}
