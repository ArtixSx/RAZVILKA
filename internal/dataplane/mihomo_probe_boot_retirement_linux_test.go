//go:build linux

package dataplane

import (
	"context"
	"net"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Historical boot metadata is a model; current boot/netns and both socket
// tables are real. This is not evidence of a physical router reboot.
func TestMihomoProbeBootRetirementActualSocketAbsence(t *testing.T) {
	m, e, _, ctx, _ := mihomoRetirementFixture(t)
	provider := netidentity.NewProcProvider()
	current, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.BootID == e.Resources[0].MihomoProbe.NetworkIdentity.BootID {
		t.Fatal("model old boot matches live kernel")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:18090")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	guard := func(c context.Context) error { return c.Err() }
	if result, err := m.RetireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard); err == nil || result.PlanID != "" {
		t.Fatal("occupied actual loopback port accepted", result, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RetireMihomoProbeAfterBoot(ctx, e.PlanID, e.Digest, guard); err != nil {
		t.Fatal("actual complete socket absence failed", err)
	}
	if err := m.CheckExecutionRecovery(ctx); err != nil {
		t.Fatal(err)
	}
}
