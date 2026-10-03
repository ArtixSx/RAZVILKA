package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestWGCanaryPolicyIsDeviceScopedAndDeletesExactRoute(t *testing.T) {
	for _, source := range []string{"10.66.0.2", "2001:db8:66::2"} {
		r := &warpFakeRunner{}
		a := NewWireGuardAdapter(nil, t.TempDir())
		a.Interface, a.Table, a.PriorityBase, a.IP, a.Runner = "rz-wg-canary", 219, 18050, "ip", r
		ip := netip.MustParseAddr(source)
		if err := a.installCanaryPolicy(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
		if err := a.cleanupCanaryPolicy(context.Background(), ip); err != nil {
			t.Fatal(err)
		}
		calls := strings.Join(r.calls, "\n")
		for _, fragment := range []string{"oif rz-wg-canary lookup 219", "route del default dev rz-wg-canary table 219"} {
			if !strings.Contains(calls, fragment) {
				t.Fatalf("missing %s: %s", fragment, calls)
			}
		}
		if strings.Contains(calls, "flush") {
			t.Fatal("cleanup flushed foreign routes")
		}
		if ip.Is6() && !strings.Contains(calls, "ip -6 rule add priority 18050 from "+source+"/128") {
			t.Fatal(calls)
		}
	}
}

func TestWGCanaryTCPAndUDPBindTheSelectedDevice(t *testing.T) {
	ctx := context.WithValue(context.Background(), wgSocketInterfaceKey{}, "rz-wg-canary")
	for _, udp := range []bool{false, true} {
		dialer := wgSocketDialer(ctx, net.ParseIP("2001:db8:66::2"), udp)
		if dialer.Control == nil || !strings.Contains(dialer.LocalAddr.String(), "2001:db8:66::2") {
			t.Fatal("socket lost candidate device/source")
		}
	}
}

type wgCanaryForeignFamily struct{ warpFakeRunner }

func (r *wgCanaryForeignFamily) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == "-6 route show table 219" {
		return []byte("2001:db8::/64 dev foreign"), nil
	}
	return r.warpFakeRunner.Run(ctx, name, args...)
}

func TestWGCanaryRejectsForeignIPv6TableBeforeMutation(t *testing.T) {
	r := &wgCanaryForeignFamily{}
	a := NewWireGuardAdapter(nil, t.TempDir())
	a.IP, a.Table, a.PriorityBase, a.Runner = "ip", 219, 18050, r
	if err := a.ensureCanaryPolicyFree(context.Background()); err == nil {
		t.Fatal("foreign IPv6 table accepted")
	}
	for _, call := range r.calls {
		if strings.Contains(call, " add ") || strings.Contains(call, " del ") {
			t.Fatal(call)
		}
	}
}

func TestWGCanaryOnlyIPv6AddressSupported(t *testing.T) {
	source, err := firstTunnelAddress([]string{"2001:db8:66::2/128"})
	if err != nil || !source.Is6() {
		t.Fatal(source, err)
	}
	if _, err := firstTunnelAddress([]string{"invalid"}); err == nil {
		t.Fatal("invalid address accepted")
	}
}

type wgMissingTableRunner struct{}

func (wgMissingTableRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if strings.Contains(strings.Join(args, " "), "route show table") {
		return []byte("Error: ipv4: FIB table does not exist."), errors.New("exit status 2")
	}
	return nil, nil
}

func TestWGCanarySupportsAbsentFIBOnColdBoot(t *testing.T) {
	a := NewWireGuardAdapter(nil, t.TempDir())
	a.IP, a.Runner = "ip", wgMissingTableRunner{}
	if err := a.ensureCanaryPolicyFree(context.Background()); err != nil {
		t.Fatal(err)
	}
}
