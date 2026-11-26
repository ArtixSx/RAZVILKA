//go:build linux

package physicalscope

import "context"

// The existing read-only transport validates sender/sequence/port, complete
// multipart DONE, loss/interruption, bounds and unsolicited trailing data.
// The caller brackets this fixed dump with the original provider and fence.
func readPrimaryIPv4Dump(ctx context.Context) ([]message, error) { return dump(ctx, 22, 2) }
