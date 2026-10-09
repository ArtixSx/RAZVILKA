package dataplane

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestSyntheticBaselineEffectsRefuseMissingOriginalMapping(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	for _, mapping := range []*dnscontrol.SyntheticDNSMapping{nil, new(dnscontrol.SyntheticDNSMapping)} {
		if _, err := SyntheticBaselineTransitionEffects(context.Background(), transport, domain, mapping); err == nil {
			t.Fatal("metadata substituted for original mapping")
		}
	}
}

func TestSyntheticBaselineEffectsExactRestorativeTupleAndDependencies(t *testing.T) {
	// Comparison-only serializer model; no native additions or readiness.
	record := dnscontrol.SyntheticDNSMappingObservation{Authority: dnscontrol.NetworkPolicyDNSAuthority{Generation: strings.Repeat("a", 64)}, PublicationID: strings.Repeat("b", 32), Client: netip.MustParseAddr("192.168.1.42"), DeviceID: "selected", MAC: "02:00:00:00:00:02", Ingress: "br0", QName: "service.example.com", Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: netip.MustParseAddr("93.184.215.14")}
	plan, err := syntheticBaselineTransitionEffects(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Effects) != 4 || !slices.Equal(plan.Effects[1].Needs, []int{0}) {
		t.Fatal("DNAT body lacks chain dependency")
	}
	for i, port := range []string{"80", "443"} {
		effect := plan.Effects[i+2]
		if effect.Tool != PolicyEffectIPTables || !slices.Equal(effect.Needs, []int{0, 1}) || !slices.Equal(effect.Add[3:len(effect.Add)-1], []string{"PREROUTING", "-i", "br0", "-s", "192.168.1.42/32", "-d", "198.18.0.1/32", "-m", "mac", "--mac-source", "02:00:00:00:00:02", "-p", "tcp", "-m", "tcp", "--dport", port, "-j"}) {
			t.Fatal("restorative selector widened", effect)
		}
		if effect.Delete[2] != "-D" || !slices.Equal(effect.Delete[3:], effect.Add[3:]) {
			t.Fatal("deletion differs from exact tuple")
		}
	}
	for _, effect := range plan.Effects {
		if effect.Tool != PolicyEffectIPTables || slices.Contains(effect.Add, "--mark") || slices.Contains(effect.Add, "CONNMARK") || slices.Contains(effect.Add, "MARK") || slices.Contains(effect.Add, "-F") || slices.Contains(effect.Add, "-Z") {
			t.Fatal("baseline rewrote positive/foreign policy", effect)
		}
	}
	other := record
	other.MAC = "02:00:00:00:00:03"
	changed, err := syntheticBaselineTransitionEffects(other)
	if err != nil || slices.Equal(plan.Effects[0].Add, changed.Effects[0].Add) {
		t.Fatal("different client ownership collided", err)
	}
}
