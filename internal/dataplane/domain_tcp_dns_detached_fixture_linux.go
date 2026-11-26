//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
)

var ErrNativeDomainDNSDetachmentACK = errors.New("native fixture lost original DNS detachment ACK")

// An error-only fixture seam, never a replacement owner, positive proof or
// writer. Every actual original admission/rename/sync/registry action remains
// mandatory. The one-shot error is delivered only AFTER the named real ACK.
func ConfigureNativeDomainDNSDetachmentACK(ctx context.Context, o *DomainTCPOriginalScope, stage string) error {
	if o == nil || o.self != o || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if stage != "alias0" && stage != "alias1" && stage != "global" && stage != "registry" {
		return ErrDomainPolicyTCPConsumer
	}
	for _, name := range []string{"net", "mnt"} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		initial, e2 := os.Readlink("/proc/1/ns/" + name)
		if os.Geteuid() != 0 || err != nil || e2 != nil || current == initial {
			return ErrDomainPolicyTCPConsumer
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.dnsDetachment != nil || o.dnsDetachmentFault != nil || o.standbyOwner == nil || o.standbyOwner.original != o {
		return ErrDomainPolicyTCPConsumer
	}
	var used atomic.Bool
	o.dnsDetachmentFault = func(actual string) error {
		if actual == stage && used.CompareAndSwap(false, true) {
			return ErrNativeDomainDNSDetachmentACK
		}
		return nil
	}
	return nil
}
