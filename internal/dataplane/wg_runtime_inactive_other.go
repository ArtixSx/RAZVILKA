//go:build !linux

package dataplane

import "context"

func verifyWGProcessesInactive(context.Context, []string) error { return errWGInactiveUnknown }
