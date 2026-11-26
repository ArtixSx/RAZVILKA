//go:build !linux || (!amd64 && !arm64)

package physicalscope

import "context"

func readScopeOptions(ctx context.Context) (ScopeOptionsObservation, error) {
	return unavailableScopeOptions("SOURCE_UNAVAILABLE"), ErrUnknown
}
