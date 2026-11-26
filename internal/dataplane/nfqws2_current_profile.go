package dataplane

import (
	"bytes"
	"context"
	"reflect"
	"time"
)

// NFQWS2CurrentDomainOnlyProfile identifies only this manager's confirmed
// running first-start profile. This is denial-only advice before an app probe,
// never execution authority or a claim about an external NFQWS2 configuration.
// Unknown, stopped or changed receipts deliberately produce no classification.
func (m *Manager) NFQWS2CurrentDomainOnlyProfile(ctx context.Context) bool {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if m.beginOperation(ctx) != nil {
		return false
	}
	defer m.endOperation()
	adapter, _ := m.adapter("nfqws2")
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a.stockNativeOwner == nil {
		return false
	}
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.FirstStart == nil || lease.FirstStart.Phase != nfqws2FirstRunning || lease.FirstStart.Process == nil {
		return false
	}
	if _, err := a.verifyOwnedLists(false); err != nil || a.verifyFirstStartRunning(ctx) != nil {
		return false
	}
	committed, exists, err := m.Committed()
	if err != nil || !exists || committed.State != "committed" {
		return false
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return false
	}
	expected, err := a.firstStartConfig(committed, config)
	if err != nil || !bytes.Equal(expected, config) {
		return false
	}
	// Classification must belong to the same current receipt and image at
	// both bookends. No journal, lock marker or runtime object is created.
	closing, err := a.readLease()
	if err != nil || !reflect.DeepEqual(closing, lease) || a.verifyFirstStartRunning(ctx) != nil {
		return false
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return false
	}
	registered, _ := m.adapter("nfqws2")
	if registered != adapter {
		return false
	}
	current, exists, err := m.Committed()
	return err == nil && exists && reflect.DeepEqual(current, committed) && ctx.Err() == nil
}
