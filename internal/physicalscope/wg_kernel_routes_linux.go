//go:build linux

package physicalscope

import "context"

func platformWGKernelRoutes(ctx context.Context, family byte) ([]message, error) {
	return dump(ctx, 26, family)
}
