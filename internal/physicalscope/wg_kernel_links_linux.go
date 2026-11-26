//go:build linux

package physicalscope

import "context"

func platformWGKernelLinks(ctx context.Context) ([]message, error) { return dump(ctx, 18, 0) }
