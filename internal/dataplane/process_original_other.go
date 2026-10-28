//go:build !linux

package dataplane

import "context"

func originalProcessPIDAbsent(int) error                       { return ErrOriginalProcessCleanup }
func originalProcessListenerAbsent(context.Context, int) error { return ErrOriginalProcessCleanup }
