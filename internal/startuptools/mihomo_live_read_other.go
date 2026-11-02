//go:build !linux || (!amd64 && !arm64)

package startuptools

import "context"

func (l *Lease) runMihomoLiveRead(context.Context, string, ...string) ([]byte, error) {
	return nil, at("PLATFORM", nil)
}
