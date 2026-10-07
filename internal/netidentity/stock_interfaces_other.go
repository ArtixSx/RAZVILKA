//go:build !linux || (!amd64 && !arm64)

package netidentity

import "context"

func (*Provider) ReadReviewedStockInterfaces(context.Context) ([]byte, error) {
	return nil, ErrUnknown
}
