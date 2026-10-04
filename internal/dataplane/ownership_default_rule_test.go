package dataplane

import (
	"context"
	"strings"
	"testing"
)

func TestManagedDefaultPolicyAcceptsNativeOmittedDestinationReadbackAndCleanup(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := newProxyLANFixture(t)
		source, destination := "192.168.1.0/24", "0.0.0.0/0"
		if v6 {
			source, destination = "fd84:db59:da10::/64", "::/0"
		}
		state := f.policy(v6, source)
		state.NetworkPolicyGeneration, state.NetworkDefault = strings.Repeat("a", 64), true
		state.Prefixes = []string{destination}
		state.Rules[0].Destination, state.Rules[0].Ingress, state.Rules[0].Managed = destination, "br0", true
		initializePolicyLayout(&state)
		base := f.a.Runner
		runner := networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
			output, err := base.Run(ctx, name, args...)
			if strings.Contains(strings.Join(args, " "), "rule show") {
				return []byte(strings.ReplaceAll(string(output), " to "+destination, "")), err
			}
			return output, err
		})
		if err := applyPolicy(context.Background(), runner, "ip", state); err != nil {
			t.Fatal("default policy installation with native readback", v6, err)
		}
		if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err != nil {
			t.Fatal("default native readback refused", v6, err)
		}
		if err := removePolicy(context.Background(), runner, "ip", state); err != nil {
			t.Fatal("default cleanup could not identify its exact rule", v6, err)
		}
	}
}

func TestKernelPolicyDefaultRuleNormalizesOnlyOmittedDestination(t *testing.T) {
	for _, family := range []int{4, 6} {
		source, destination := "192.168.93.0/24", "0.0.0.0/0"
		if family == 6 {
			source, destination = "fd93::/64", "::/0"
		}
		for _, selectors := range []string{"", "iif rz-def-lan ", "fwmark " + LANPolicyGateMatch + " iif rz-def-lan "} {
			for _, table := range []string{"lookup 204", "table 204"} {
				omitted := "67: from " + source + " " + selectors + table
				explicit := "67: from " + source + " to " + destination + " " + selectors + table
				got, ok := parseKernelPolicyRule(family, omitted)
				want, explicitOK := parseKernelPolicyRule(family, explicit)
				if !ok || !explicitOK || got != want || got.destination != destination || got.family != family {
					t.Fatal("omitted default destination lost exact tuple", family, omitted, got, want)
				}
			}
		}
	}
}

func TestKernelPolicyOmittedDefaultRejectsUnknownOrChangedSelectors(t *testing.T) {
	for _, family := range []int{4, 6} {
		source, wrongFamily := "192.168.93.0/24", "fd93::/64"
		if family == 6 {
			source, wrongFamily = wrongFamily, source
		}
		good := "67: from " + source + " fwmark " + LANPolicyGateMatch + " iif rz-def-lan lookup 204"
		for _, line := range []string{
			strings.Replace(good, source, wrongFamily, 1),
			strings.Replace(good, LANPolicyGateMatch, "0x20000000/0x20000000", 1),
			strings.Replace(good, LANPolicyGateMatch, "0x20000000", 1),
			strings.Replace(good, " iif rz-def-lan", "", 1),
			strings.Replace(good, " iif rz-def-lan", " iif rz-def-lan oif foreign0", 1),
			strings.Replace(good, "fwmark", "not fwmark", 1),
			strings.Replace(good, "lookup 204", "goto 204", 1),
			strings.Replace(good, "lookup 204", "lookup 204 suppress_prefixlength 0", 1),
			strings.Replace(good, "lookup 204", "lookup 204 uidrange 0-10", 1),
			strings.Replace(good, "lookup 204", "lookup 0204", 1),
			strings.Replace(good, "67:", "067:", 1),
			good + " extra",
		} {
			if _, ok := parseKernelPolicyRule(family, line); ok {
				t.Fatal("unreviewed default selector accepted", family, line)
			}
		}
	}
	for _, line := range []string{"", "67:", "67: from all lookup"} {
		if _, ok := parseKernelPolicyRule(4, line); ok {
			t.Fatal("short rule accepted")
		}
	}
}
