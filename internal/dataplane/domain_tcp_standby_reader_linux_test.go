//go:build linux

package dataplane

import (
	"context"
	"testing"
)

func TestDomainTCPStandbyRetainedRequiresReader4AndKeepsRecoveryFence(t *testing.T) {
	root := t.TempDir()
	e := executionSyntheticResourceFixture(t)
	e.State, e.Resources[0].Phase = "resource-failed", "standby-retained"
	m := New(root)
	if err := m.writeExecution(root, e); err != nil {
		t.Fatal(err)
	}
	if version, _, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 4 {
		t.Fatal(version, err)
	}
	if err := m.CheckExecutionRecovery(context.Background()); err == nil {
		t.Fatal("cold standby metadata adopted as active owner")
	}
	if err := validateExecutionResources(e, true); err == nil {
		t.Fatal("retained restorative intent became terminal service result")
	}
}
