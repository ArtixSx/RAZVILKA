package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type ingressEvidenceRunner struct {
	calls           []string
	source, forward string
	connected       string
	connectedErr    error
	sourceErr       error
}

func (r *ingressEvidenceRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if strings.Contains(command, "route show table main match") {
		return []byte(r.connected), r.connectedErr
	}
	if strings.Contains(command, "route get 192.168.1.40") || strings.Contains(command, "route get fd00::40") {
		return []byte(r.source), r.sourceErr
	}
	return []byte(r.forward), nil
}

func TestPolicyEvidenceUsesForwardedDeviceIngress(t *testing.T) {
	for _, tc := range []struct{ name, source, dest, reverse, forward, want string }{
		{"ipv4", "192.168.1.40/32", "149.154.160.0/20", "192.168.1.40 dev br0 src 192.168.1.1", "149.154.160.0 from 192.168.1.40 dev rz-sing table 203", "route get 149.154.160.0 from 192.168.1.40 iif br0"},
		{"ipv6", "fd00::40/128", "2001:b28:f23d::/48", "fd00::40 dev br0 src fd00::1", "2001:b28:f23d:: from fd00::40 dev rz-sing table 203", "-6 route get 2001:b28:f23d:: from fd00::40 iif br0"},
		{"router-local", "192.168.1.40/32", "149.154.160.0/20", "local 192.168.1.40 dev lo src 192.168.1.40", "149.154.160.0 dev rz-sing", "route get 149.154.160.0 from 192.168.1.40"},
		{"router-local-ipv6", "fd00::40/128", "2001:b28:f23d::/48", "local fd00::40 from :: dev lo table local proto kernel metric 0", "2001:b28:f23d:: from fd00::40 dev rz-sing table 203", "-6 route get 2001:b28:f23d:: from fd00::40"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &ingressEvidenceRunner{source: tc.reverse, forward: tc.forward, connected: "192.168.1.0/24 dev br0 proto kernel scope link src 192.168.1.1\nfd00::/64 dev br0 proto kernel metric 256"}
			state := PolicyState{Interface: "rz-sing", Rules: []PolicyRule{{Source: tc.source, Destination: tc.dest}}}
			if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err != nil {
				t.Fatal(err)
			}
			wantCalls := 3
			if strings.HasPrefix(tc.name, "router-local") {
				wantCalls = 2
			}
			if len(runner.calls) != wantCalls || runner.calls[len(runner.calls)-1] != tc.want {
				t.Fatalf("calls=%v", runner.calls)
			}
		})
	}
}

func TestPolicyEvidenceDoesNotGuessIngressFromRoutedOrAmbiguousSources(t *testing.T) {
	for _, tc := range []struct{ name, reverse, connected string }{
		{"gateway-return-path", "192.168.1.40 via 100.64.0.1 dev eth3", "192.168.1.0/24 dev br0 scope link"},
		{"point-to-point-default", "192.168.1.40 dev ppp0 src 100.64.0.2", "default dev ppp0 scope link"},
		{"different-connected-interface", "192.168.1.40 dev br1 src 192.168.1.1", "192.168.1.0/24 dev br0 scope link"},
		{"duplicate-lan-subnet", "192.168.1.40 dev br0 src 192.168.1.1", "192.168.1.0/24 dev br0 scope link\n192.168.1.0/24 dev br1 scope link"},
		{"broadcast-source", "broadcast 192.168.1.40 dev br0", "192.168.1.0/24 dev br0 scope link"},
		{"missing-connected-route", "192.168.1.40 dev br0", ""},
		{"multipath-source", "192.168.1.40 dev br0", "192.168.1.0/24 nexthop dev br0 weight 1 nexthop dev br1 weight 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &ingressEvidenceRunner{source: tc.reverse, connected: tc.connected, forward: "149.154.160.0 from 192.168.1.40 dev rz-sing table 203"}
			state := PolicyState{Interface: "rz-sing", Rules: []PolicyRule{{Source: "192.168.1.40/32", Destination: "149.154.160.0/20"}}}
			if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err == nil {
				t.Fatal("unproven ingress produced route evidence")
			}
		})
	}
}

func TestPolicyEvidenceRejectsUnknownIngressAndWrongTunnel(t *testing.T) {
	for _, tc := range []struct {
		name, source, forward string
		err                   error
	}{
		{"missing-source", "", "dev rz-sing", errors.New("unreachable")},
		{"ambiguous-source", "dev br0 dev br1", "dev rz-sing", nil},
		{"source-tunnel", "dev rz-sing", "dev rz-sing", nil},
		{"source-loopback", "dev lo", "dev rz-sing", nil},
		{"similarly-named-tunnel", "dev br0", "dev rz-sing-foreign", nil},
		{"wrong-tunnel", "dev br0", "dev opkgtun0", nil},
		{"nonunicast-forward", "dev br0", "local 149.154.160.0 dev rz-sing", nil},
		{"ambiguous-forward", "dev br0", "149.154.160.0 dev rz-sing\n149.154.160.0 dev br1", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &ingressEvidenceRunner{source: tc.source, forward: tc.forward, sourceErr: tc.err, connected: "192.168.1.0/24 dev br0 scope link"}
			state := PolicyState{Interface: "rz-sing", Rules: []PolicyRule{{Source: "192.168.1.40/32", Destination: "149.154.160.0/20"}}}
			if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err == nil {
				t.Fatal("invalid route accepted")
			}
		})
	}
}

func TestPolicyEvidenceChecksFamiliesContextAndCachesConnectedIngress(t *testing.T) {
	state := PolicyState{Interface: "rz-sing", Rules: []PolicyRule{{Source: "192.168.1.40/32", Destination: "2001:b28:f23d::/48"}}}
	runner := &ingressEvidenceRunner{source: "192.168.1.40 dev br0", connected: "192.168.1.0/24 dev br0 scope link", forward: "dev rz-sing"}
	if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err == nil || len(runner.calls) != 0 {
		t.Fatal("cross-family probe reached kernel")
	}
	state.Rules = []PolicyRule{{Source: "192.168.1.40/32", Destination: "149.154.160.0/20"}, {Source: "192.168.1.40/32", Destination: "91.108.4.0/22"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyPolicyEvidence(ctx, runner, "ip", state); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatal("canceled proof acquired authority")
	}
	if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 || runner.calls[1] != "route show table main match 192.168.1.40/32" {
		t.Fatalf("source lookup was not bounded/reused: %v", runner.calls)
	}
	runner.calls = nil
	runner.connectedErr = errors.New("unsupported match")
	if err := verifyPolicyEvidence(context.Background(), runner, "ip", state); err == nil || len(runner.calls) != 2 {
		t.Fatal("missing connected-source capability was accepted")
	}
}
