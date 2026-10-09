//go:build !linux

package physicalscope

import "context"

func readPrimaryIPv4Dump(context.Context) ([]message, error) { return nil, ErrUnknown }
