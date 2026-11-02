package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
)

func mihomoProbeDefinitionFixture(t *testing.T) ExecutionMihomoProbeDefinition {
	t.Helper()
	x := xrayDomainExecutionDefinitionFixture(t)
	return ExecutionMihomoProbeDefinition{Schema: 1, PlanID: x.PlanID, PlanDigest: x.PlanDigest, NetworkProfile: x.NetworkProfile, Revision: 1, NetworkIdentity: x.NetworkIdentity, Service: x.Service,
		Source: components.MihomoProbeReference{Version: components.ReviewedMihomoVersion, BinarySHA256: strings.Repeat("a", 64), BinarySize: 62017662, ReviewSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), ServerHost: "edge.example", Endpoint: netip.MustParseAddr("1.1.1.2"), SOCKSPort: 18090}}
}

func TestMihomoProbeIntentIsClosedAndNeverAdoptsRuntime(t *testing.T) {
	d := mihomoProbeDefinitionFixture(t)
	if err := d.validate(); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"planned", "process-pending", "listener-ready", "closed", "removed", "unused"} {
		state := "prepared"
		if phase == "removed" || phase == "unused" {
			state = phase
		}
		r := ExecutionResource{ID: "mp-" + strings.Repeat("a", 32), Kind: "mihomo-probe", State: state, Phase: phase, Generation: d.Source.ConfigSHA256, EffectsDigest: d.Source.ConfigSHA256, MihomoProbe: &d}
		e := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, State: "checking", Resources: []ExecutionResource{r}}
		if err := validateExecutionResources(e, false); err != nil {
			t.Fatal(phase, err)
		}
		if err := validateExecutionResources(e, true); (err == nil) != (state != "prepared") {
			t.Fatal("wrong terminal classification", phase, err)
		}
		cloned := cloneExecutionResources(e.Resources)
		cloned[0].MihomoProbe.Source.ServerHost = "changed.example"
		cloned[0].MihomoProbe.Service.Domains[0] = "changed.example"
		if d.Source.ServerHost != "edge.example" || d.Service.Domains[0] == "changed.example" {
			t.Fatal("clone retained mutable alias")
		}
	}
	for _, change := range []func(*ExecutionMihomoProbeDefinition){
		func(d *ExecutionMihomoProbeDefinition) { d.Source.Endpoint = netip.MustParseAddr("127.0.0.1") },
		func(d *ExecutionMihomoProbeDefinition) { d.Source.SOCKSPort = 8787 },
		func(d *ExecutionMihomoProbeDefinition) { d.Source.Version = "unreviewed" },
		func(d *ExecutionMihomoProbeDefinition) { d.Revision = 0 },
		func(d *ExecutionMihomoProbeDefinition) { d.Source.ServerHost = "1.1.1.3" },
		func(d *ExecutionMihomoProbeDefinition) { d.Source.ConfigSHA256 = "unreviewed" },
	} {
		copy := d.Clone()
		change(&copy)
		if copy.validate() == nil {
			t.Fatal("changed intent accepted")
		}
	}
}
