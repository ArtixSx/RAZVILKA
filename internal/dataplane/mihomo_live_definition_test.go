package dataplane

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
)

func mihomoLiveDefinitionFixture(t *testing.T) ExecutionMihomoLiveDefinition {
	t.Helper()
	x := mihomoProbeDefinitionFixture(t)
	x.NetworkProfile = "wan-" + strings.Repeat("a", 12)
	image := components.ReviewedMihomoRuntimeImages()[0]
	node := "node-" + strings.Repeat("1", 64)
	service := catalog.Service{ID: "listed", Name: "Listed fixture", Category: "fixture", Strategy: []string{"mihomo"}, ProbeURL: "https://1.1.1.1/", CIDRs: []string{"1.1.1.0/24"}}
	plan := Plan{SchemaVersion: SchemaVersion, PlanID: x.PlanID, Digest: x.PlanDigest, Revision: 1, Ready: true, RouteCount: 1, NetworkProfileID: x.NetworkProfile, Adapters: []string{"mihomo"}, CanaryAdapters: []string{"mihomo"}, Routes: []Route{{ServiceID: service.ID, LogicalServiceID: service.ID, Selected: "mihomo:" + node, Resolved: "mihomo:" + node, CIDRs: []string{"1.1.1.0/24"}, Sources: []string{"192.168.1.2/32"}, ProbeURL: service.ProbeURL, ProbeService: &service}}}
	parent := components.MihomoProbeParentOrigin{Schema: 1, BootID: x.NetworkIdentity.BootID, PID: 2, StartTicks: 3, ExecutableInode: 4, ExecutableSize: 10, ExecutableSHA256: strings.Repeat("d", 64), PIDNamespaceInode: 5, ProcInode: 6, DeathSignal: "linux-pdeathsig-sigkill-v1"}
	d := ExecutionMihomoLiveDefinition{Schema: 1, Plan: plan, Source: components.MihomoLiveReference{Schema: 1, Version: components.ReviewedMihomoVersion, BinarySHA256: image.SHA256, BinarySize: image.Size, ParentOrigin: parent}, Node: NodeDefaultSourceReference{Schema: 1, EngineID: "mihomo", NodeID: node, Resolved: "mihomo:" + node, NodeGeneration: 1, MaterialSHA256: strings.Repeat("b", 64)}, Profile: components.MihomoLiveProfileReference{ConfigSHA256: strings.Repeat("c", 64), SOCKSPort: 18090}, Service: service, NetworkProfile: x.NetworkProfile, NetworkIdentity: x.NetworkIdentity, EndpointHost: "edge.example", Endpoint: netip.MustParseAddr("2.2.2.2"), EndpointAddresses: []netip.Addr{netip.MustParseAddr("2.2.2.2")}, Sidecar: MihomoLiveSidecarReference{Kind: "hev", BinarySHA256: strings.Repeat("e", 64), BinarySize: 10, ConfigSHA256: strings.Repeat("f", 64)}, Policy: PolicyState{Interface: "rz-mihomo", Table: 207, PriorityBase: 31200, RuleLayout: 2, SharedPriorityBase: 78, Prefixes: []string{"1.1.1.0/24"}, Rules: []PolicyRule{{Source: "192.168.1.2/32", Destination: "1.1.1.0/24"}}, Exclusions: []string{"2.2.2.2/32"}, Forwarding: &ProxyForwardingState{Chain: "RZP_123456789abc", Rules: []ProxyForwardingRule{{Source: "192.168.1.2/32", Destination: "1.1.1.0/24", Ingress: "br0"}}}}}
	d.Service, _ = FrozenProbeService(d.Plan.Routes[0])
	if err := d.validate(); err != nil {
		t.Fatal("fixture", err)
	}

	return d
}

func TestMihomoLiveDefinitionRejectsWidenedPolicyAndPreservesFrozenIdentity(t *testing.T) {
	d := mihomoLiveDefinitionFixture(t)
	digest, _ := d.FrozenDigest()
	d.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
	if got, err := d.FrozenDigest(); err != nil || got != digest || d.validateActive() != nil {
		t.Fatal("actual observation changed immutable intent", got, err)
	}
	for name, change := range map[string]func(*ExecutionMihomoLiveDefinition){
		"widen-source":              func(d *ExecutionMihomoLiveDefinition) { d.Policy.Rules[0].Source = "192.168.1.0/24" },
		"widen-destination":         func(d *ExecutionMihomoLiveDefinition) { d.Policy.Rules[0].Destination = "0.0.0.0/0" },
		"remove-endpoint-exclusion": func(d *ExecutionMihomoLiveDefinition) { d.Policy.Exclusions = nil },
		"unrelated-exclusion": func(d *ExecutionMihomoLiveDefinition) {
			d.Policy.Exclusions = append(d.Policy.Exclusions, "9.9.9.9/32")
		},
		"widen-forward":        func(d *ExecutionMihomoLiveDefinition) { d.Policy.Forwarding.Rules[0].Source = "0.0.0.0/0" },
		"loopback-forward":     func(d *ExecutionMihomoLiveDefinition) { d.Policy.Forwarding.Rules[0].Ingress = "lo" },
		"wrong-receipt-reader": func(d *ExecutionMihomoLiveDefinition) { d.Observation.SidecarReceiptVersion = 2 },
		"wrong-network":        func(d *ExecutionMihomoLiveDefinition) { d.Source.ParentOrigin.BootID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := d.Clone()
			change(&copy)
			if copy.validate() == nil {
				t.Fatal("changed comparison accepted")
			}
		})
	}
	copy := d.Clone()
	copy.Policy.Forwarding.Rules[0].Ingress = "br1"
	copy.Plan.Routes[0].Sources[0] = "192.168.1.3/32"
	copy.Service.CIDRs[0] = "9.9.9.0/24"
	copy.Observation.SidecarReceiptSHA256 = strings.Repeat("b", 64)
	if d.Policy.Forwarding.Rules[0].Ingress != "br0" || d.Plan.Routes[0].Sources[0] != "192.168.1.2/32" || d.Service.CIDRs[0] != "1.1.1.0/24" || d.Observation.SidecarReceiptSHA256 != strings.Repeat("a", 64) {
		t.Fatal("mutable aliases survived clone")
	}
}

func TestMihomoLiveRecordsAreTypedIntentAndCannotAdoptActiveOwner(t *testing.T) {
	d := mihomoLiveDefinitionFixture(t)
	for _, phase := range []string{"reserved", "validation-pending", "process-pending", "listener-bound", "policy-pending", "closed", "active", "removed", "unused"} {
		copy := d.Clone()
		state := "prepared"
		if phase == "active" || phase == "sidecar-bound" || phase == "policy-pending" {
			if phase == "active" {
				state = "active"
			}
			copy.Observation = &MihomoLiveRuntimeObservation{Schema: 1, SidecarReceiptVersion: 1, SidecarReceiptSHA256: strings.Repeat("a", 64)}
		}
		if phase == "removed" || phase == "unused" {
			state = phase
		}
		digest, _ := copy.FrozenDigest()
		e := Execution{PlanID: copy.Plan.PlanID, Digest: copy.Plan.Digest, State: "committed", Resources: []ExecutionResource{{ID: "ml-" + strings.Repeat("1", 32), Kind: "mihomo-live", State: state, Phase: phase, Generation: copy.Profile.ConfigSHA256, EffectsDigest: digest, MihomoLive: &copy}}}
		if err := validateExecutionResources(e, false); err != nil {
			t.Fatal(phase, err)
		}
		if err := validateExecutionResources(e, true); (err == nil) != (state != "prepared") {
			t.Fatal("terminal classification", phase, err)
		}
		if phase == "active" {
			m := &Manager{Adapters: map[string]Adapter{}}
			if m.checkRetainedMihomoRecord(e) == nil {
				t.Fatal("decoded ACTIVE adopted")
			}
		}
		e.Resources[0].Kind = "mihomo-probe"
		if validateExecutionResources(e, false) == nil {
			t.Fatal("mixed union accepted")
		}
	}
}

func TestMihomoLiveDefinitionStrictRoundTrip(t *testing.T) {
	d := mihomoLiveDefinitionFixture(t)
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var after ExecutionMihomoLiveDefinition
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&after); err != nil {
		t.Fatal("decode", err)
	}
	if err := after.validate(); err != nil {
		t.Fatal("decoded definition invalid", err)
	}
}

func TestMihomoLiveDefinitionCannotChangePersistedServiceProbe(t *testing.T) {
	d := mihomoLiveDefinitionFixture(t)
	data, _ := json.Marshal(d)
	var after ExecutionMihomoLiveDefinition
	if err := json.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	after.Service.ProbeURL = "https://9.9.9.9/"
	if after.validate() == nil {
		t.Fatal("different persisted service accepted")
	}
}
