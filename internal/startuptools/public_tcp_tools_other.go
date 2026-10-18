//go:build !linux || (!amd64 && !arm64)

package startuptools

import "context"

func (*Lease) runPublicTCP(context.Context, string, ...string) ([]byte, error) {
	return nil, at("PUBLIC_TCP_UNSUPPORTED", nil)
}
