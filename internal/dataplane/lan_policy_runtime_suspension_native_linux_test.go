//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Called only by the coordinator's opt-in empty-netns test. It exercises real
// packet suppression and the actual common receipt. Protected-flow RETURN is
// a kernel mechanism assertion, not a physical baseline/outbound attestation.
func lanNativeSuspensionFrames(t *testing.T, runtime *LANPolicyRuntime, prior *LANPolicyRuntimePlan, priorRoot string, bridge, client *net.Interface, counts func(string) (int, int), run func(string, ...string) string) {
	t.Helper()
	var captures []LANPolicyCaptureClass
	var baseline []LANPolicyProtectedFlow
	for _, family := range []int{4, 6} {
		source, destination, protected := "192.168.77.0/24", "198.51.100.88/32", "192.168.77.43:29408"
		dstTuple := "198.51.100.88:19408"
		if family == 6 {
			source, destination, protected, dstTuple = "fd00:77::/64", "2001:db8:88::8/128", "[fd00:77::43]:29408", "[2001:db8:88::8]:19408"
		}
		captures = append(captures, LANPolicyCaptureClass{Owner: "native-routing", Generation: prior.Generation, Family: family, SegmentID: "home", Interface: "br-lan", Hook: "routing", Sources: []string{source}, Protocol: "udp", DestinationMode: "prefix", Destinations: []string{destination}, DestinationPorts: []uint16{19408}})
		baseline = append(baseline, LANPolicyProtectedFlow{Generation: prior.Generation, FlowID: "native-protected-" + strconv.Itoa(family), GrantDigest: strings.Repeat("d", 64), SegmentID: "home", Interface: "br-lan", MAC: "02:00:00:00:00:01", Source: netip.MustParseAddrPort(protected), Destination: netip.MustParseAddrPort(dstTuple), Protocol: "udp"})
	}
	plan, err := FreezeLANPolicySuspensionPlan(strings.Repeat("c", 64), prior, prior, captures, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			data, _ := json.MarshalIndent(plan, "", "  ")
			effects, _ := plan.Effects()
			expected, _ := json.MarshalIndent(effects, "", "  ")
			t.Logf("expected suspension plan=%s\neffects=%s", data, expected)
			for _, tool := range []string{runtime.IPTables, runtime.IP6Tables} {
				for _, table := range []string{"mangle", "raw", "nat", "filter"} {
					t.Logf("actual %s %s:\n%s", tool, table, run(tool, "-t", table, "-S"))
				}
			}
		}
	}()
	root := privateScopedXrayFixtureDir(t)
	guard := func(ctx context.Context, _ *LANPolicySuspensionPlan, _ PolicyEffect) error { return ctx.Err() }
	settled := false
	removed := false
	binding := &LANPolicySuspensionBinding{Runtime: runtime, FenceGuard: guard, CleanupGuard: guard, CaptureCheck: func(ctx context.Context, p *LANPolicySuspensionPlan) error {
		// Every capture/tuple in this fixture is explicitly created above;
		// no raw queue/listener/flow owner exists in its initial empty netns.
		if err := runtime.ScopeCheck(ctx, p.PriorLAN); err != nil {
			return err
		}
		for _, tool := range []string{runtime.IPTables, runtime.IP6Tables} {
			if strings.Contains(run(tool, "-t", "raw", "-S"), "NFQUEUE") {
				return ErrLANPolicyRuntime
			}
		}
		return ctx.Err()
	}, ReleaseCheck: func(ctx context.Context, _ *LANPolicySuspensionPlan) error {
		if !settled {
			return ErrPolicyAdditionUnknown
		}
		return ctx.Err()
	}}
	t.Cleanup(func() {
		if !removed {
			settled = true
			if err := binding.Remove(context.Background(), plan, priorRoot, root); err != nil {
				t.Error("native suspension cleanup:", err)
			}
		}
	})
	if err := binding.Fence(context.Background(), plan, priorRoot, root); err != nil {
		t.Fatal(err)
	}
	if err := binding.Remove(context.Background(), plan, priorRoot, root); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("unknown old flow did not retain suspension", err)
	}
	dropCount := func(tool string, family int) int {
		total := 0
		for _, chain := range lanPolicySuspensionChains(plan) {
			if chain.family != family {
				continue
			}
			for _, line := range strings.Split(run(tool, "-t", "mangle", "-L", chain.name, "-n", "-v", "-x"), "\n") {
				f := strings.Fields(line)
				if len(f) > 2 && f[2] == "DROP" {
					n, err := strconv.Atoi(f[0])
					if err != nil {
						t.Fatal(err)
					}
					total += n
				}
			}
		}
		return total
	}
	for _, family := range []int{4, 6} {
		tool, source, destination := runtime.IPTables, "192.168.77.42", "198.51.100.88"
		if family == 6 {
			tool, source, destination = runtime.IP6Tables, "fd00:77::1234", "2001:db8:88::8"
		}
		for _, device := range []struct {
			name      string
			mac       byte
			protected bool
			outside   bool
		}{{"selected-blocked", 1, false, false}, {"excluded-privacy", 2, false, true}, {"unknown-MAC", 3, false, true}, {"protected-tuple", 1, true, false}} {
			actualSource := source
			if device.protected {
				actualSource = "192.168.77.43"
				if family == 6 {
					actualSource = "fd00:77::43"
				}
			} else if device.outside && family == 6 {
				actualSource = "fd00:77::9876:abcd"
			}
			beforeS, beforeF := counts(tool)
			beforeDrop := dropCount(tool, family)
			frame := lanNativeUDPFrame(bridge.HardwareAddr, net.HardwareAddr{2, 0, 0, 0, 0, device.mac}, netip.MustParseAddr(actualSource), netip.MustParseAddr(destination))
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(unix.ETH_P_ALL))
			if err != nil {
				t.Fatal(err)
			}
			err = unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: client.Index, Protocol: uint16((unix.ETH_P_ALL<<8)&0xff00 | unix.ETH_P_ALL>>8)})
			_ = unix.Close(fd)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				afterS, afterF := counts(tool)
				afterDrop := dropCount(tool, family)
				blocked := !device.protected && !device.outside
				if blocked && afterDrop > beforeDrop && afterS == beforeS && afterF == beforeF || device.outside && afterF > beforeF && afterS == beforeS && afterDrop == beforeDrop || device.protected && afterS > beforeS && afterF == beforeF && afterDrop == beforeDrop {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("suspension family=%d device=%s service=%d→%d firmware=%d→%d drop=%d→%d", family, device.name, beforeS, afterS, beforeF, afterF, beforeDrop, afterDrop)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	settled = true
	if err := binding.Remove(context.Background(), plan, priorRoot, root); err != nil {
		t.Fatal(err)
	}
	removed = true
	for _, family := range []int{4, 6} {
		tool, source, destination := runtime.IPTables, "192.168.77.42", "198.51.100.88"
		if family == 6 {
			tool, source, destination = runtime.IP6Tables, "fd00:77::1234", "2001:db8:88::8"
		}
		beforeS, beforeF := counts(tool)
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(unix.ETH_P_ALL))
		if err != nil {
			t.Fatal(err)
		}
		frame := lanNativeUDPFrame(bridge.HardwareAddr, net.HardwareAddr{2, 0, 0, 0, 0, 1}, netip.MustParseAddr(source), netip.MustParseAddr(destination))
		err = unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: client.Index, Protocol: uint16((unix.ETH_P_ALL<<8)&0xff00 | unix.ETH_P_ALL>>8)})
		_ = unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			afterS, afterF := counts(tool)
			if afterS > beforeS && afterF == beforeF {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("settled release did not restore original gate", family, beforeS, afterS, beforeF, afterF)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Do not invoke a second Remove in cleanup: removed receipts are inventory,
	// never repeat-delete permission. Cleanup verifies the metadata instead.
	t.Cleanup(func() {
		status, err := binding.Inspect(context.Background(), plan, root)
		if err != nil || !status.Removed {
			t.Error("native removed barrier receipt:", status, err)
		}
	})
}
