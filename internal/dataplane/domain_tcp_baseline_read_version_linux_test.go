//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedExecutionReader3BaselineFlowPendingAndTerminal(t *testing.T) {
	process := xrayDomainExecutionDefinitionFixture(t)
	d := ExecutionDomainTCPBaselineDefinition{Schema: 1, Capture: ExecutionDomainTCPCaptureDefinition{Schema: 1, Process: process}, Source: netip.AddrPortFrom(process.Capture.Client.Address, 49123), Target: netip.AddrPortFrom(process.Capture.Xray.RealIP, 443), Egress: "wan0"}
	p, err := compileDomainTCPBaselineFlow(d.flowSpec())
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PolicyEffectPlanDigest(p)
	for _, phase := range []string{"planned", "prepared", "connected", "closed", "removed", "unused"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			state := "prepared"
			if phase == "removed" || phase == "unused" {
				state = phase
			}
			e := Execution{PlanID: process.PlanID, Digest: process.PlanDigest, State: "checking", Resources: []ExecutionResource{{ID: "bf-" + strings.Repeat("a", 32), Kind: "domain-tcp-baseline-flow", State: state, Phase: phase, Generation: p.Generation, EffectsDigest: digest, DomainTCPBaseline: &d}}}
			data, _ := json.Marshal(e)
			if err := os.WriteFile(filepath.Join(root, "latest-execution.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			version, seal, err := InspectRetainedExecutionReadVersion(context.Background(), root)
			if err != nil || version != 3 || seal == "" {
				t.Fatal("BF format not recognized", version, seal, err)
			}
			if New(root).CheckExecutionRecovery(context.Background()) == nil {
				t.Fatal("format classification granted recovery")
			}
		})
	}
}
