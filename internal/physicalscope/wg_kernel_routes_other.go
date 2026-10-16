//go:build !linux

package physicalscope

import "context"

func platformWGKernelRoutes(context.Context, byte) ([]message, error) { return nil, ErrUnknown }
