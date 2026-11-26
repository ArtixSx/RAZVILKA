//go:build linux

package dataplane

import (
	"context"
	"strings"
	"testing"
)

func TestMihomoProbeRequiresReader4WithoutColdRuntimeAuthority(t *testing.T) {
	d := mihomoProbeDefinitionFixture(t)
	for _, phase := range []string{"planned", "process-pending", "listener-ready", "closed", "removed", "unused"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			state := "prepared"
			if phase == "removed" || phase == "unused" {
				state = phase
			}
			e := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, State: "resource-failed", Resources: []ExecutionResource{{ID: "mp-" + strings.Repeat("a", 32), Kind: "mihomo-probe", State: state, Phase: phase, Generation: d.Source.ConfigSHA256, EffectsDigest: d.Source.ConfigSHA256, MihomoProbe: &d}}}
			m := New(root)
			if err := m.writeExecution(root, e); err != nil {
				t.Fatal(err)
			}
			if version, seal, err := InspectRetainedExecutionReadVersion(context.Background(), root); err != nil || version != 4 || seal == "" {
				t.Fatal(version, seal, err)
			}
			if m.CheckExecutionRecovery(context.Background()) == nil {
				t.Fatal("readable format adopted a failed runtime")
			}
		})
	}
}
