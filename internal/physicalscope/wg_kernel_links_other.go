//go:build !linux

package physicalscope

import "context"

func platformWGKernelLinks(context.Context) ([]message, error) { return nil, ErrUnknown }
