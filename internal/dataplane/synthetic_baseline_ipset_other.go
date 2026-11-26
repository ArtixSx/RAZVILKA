//go:build !linux

package dataplane

import "context"

func openSyntheticIPSetSession(context.Context) (syntheticIPSetSession, error) {
	return nil, syntheticIPSetFailure("platform")
}
