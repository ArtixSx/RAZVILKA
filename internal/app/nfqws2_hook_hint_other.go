//go:build !linux

package app

import "context"

// Only Linux routers run NDM hooks; elsewhere the 30-second node-recovery
// schedule alone observes the owned NFQWS2 graph.
func runNFQWS2HookHint(context.Context, string, nfqws2HookHintTiming, func() bool) {}
