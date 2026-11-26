package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type nodeRouterForbiddenRunner struct{}

func (nodeRouterForbiddenRunner) Run(context.Context, string, ...string) ([]byte, error) {
	panic("authority refusal reached kernel commands")
}

func TestNodeRouterHealthRequiresReviewAndIssuerBeforeReadback(t *testing.T) {
	refuse := errors.New("review refused")
	a := &ProxyTunnelAdapter{EngineID: "xray", scopedXray: true, nodeRouterVerifier: true, Runner: nodeRouterForbiddenRunner{},
		FreshProfile: func(context.Context) (string, error) { panic("network readback preceded authority") },
		NodeRoutes: func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
			panic("materialization preceded authority")
		},
		NodeTUNProbe: func(context.Context, NodeTUNRequest) (NodeTUNObservation, error) {
			panic("LAN probe preceded authority")
		}}
	for _, ctx := range []context.Context{context.Background(), WithReviewGuard(context.Background(), func(context.Context) error { return refuse }),
		WithReviewGuard(context.Background(), func(context.Context) error { return nil })} {
		if err := a.scopedNodeRouterHealth(ctx, Plan{}, PolicyState{}, ""); err == nil {
			t.Fatal("missing review or registered issuer was accepted")
		}
	}
}

func TestNodeRouterAdmittedPinsRequireFrozenPredicateAndMaterializedScope(t *testing.T) {
	service := proxyPredicateFixtureService()
	route := Route{ServiceID: service.ID, ProbeURL: service.ProbeURL, ProbeService: &service}
	manifest := proxyNodeManifest{Routes: []Route{route}, Requests: []NodeRouteRequest{{Destinations: []string{"1.1.1.0/24", "8.8.8.8/32"}}},
		Endpoints: []proxyNodeEndpoint{{IP: "9.9.9.9"}}}
	a := &ProxyTunnelAdapter{EngineID: "xray", Interface: "rz-xray", Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, nil
	}}
	source := netip.MustParseAddr("172.31.254.1")
	probes, err := a.nodeRouterAdmittedProbes(context.Background(), manifest, source, 10)
	if err != nil || len(probes) != 2 || probes[0].request.Source != source || probes[0].request.ServiceID != service.ID || !probes[0].request.Predicate.matches(service.ID, service.ProbeURL) {
		t.Fatal("admitted exact pins lost their frozen identity", err)
	}
	manifest.Routes[0].ProbeService = nil
	if _, err := a.nodeRouterAdmittedProbes(context.Background(), manifest, source, 10); err == nil {
		t.Fatal("missing predicate was reconstructed from URL")
	}
	manifest.Routes[0] = route
	manifest.Requests[0].Destinations = []string{"1.1.1.1/32"}
	if _, err := a.nodeRouterAdmittedProbes(context.Background(), manifest, source, 10); err == nil {
		t.Fatal("fresh DNS expanded configured Xray IP scope")
	}
	manifest.Requests[0].Destinations = []string{"0.0.0.0/0"}
	manifest.Endpoints[0].IP = "8.8.8.8"
	if _, err := a.nodeRouterAdmittedProbes(context.Background(), manifest, source, 10); err == nil {
		t.Fatal("service pin overlaps backend endpoint")
	}
}

func TestNodeRouterOwnedSocketReadbackPreservesFullTupleAndInode(t *testing.T) {
	encode := func(address netip.Addr, port uint16) string {
		bytes := address.As4()
		return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(bytes[:]), port)
	}
	local := netip.MustParseAddr("192.0.2.2")
	remote := netip.MustParseAddr("9.9.9.9")
	row := fmt.Sprintf("0: %s %s 01 00000000:00000000 00:00000000 00000000 0 0 100\n", encode(local, 30000), encode(remote, 443))
	raw := []byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + row)
	sockets, err := nodeRouterOwnedSockets(raw, false, map[string]bool{"100": true})
	if err != nil || len(sockets) != 1 || sockets[0].local.Addr() != local || sockets[0].remote != netip.AddrPortFrom(remote, 443) {
		t.Fatal("owned socket tuple changed", err)
	}
	if err := nodeRouterSocketDisjoint(sockets[0], netip.MustParseAddr("172.31.254.1"), netip.MustParseAddr("1.1.1.1"), map[netip.Addr]bool{remote: true}); err != nil {
		t.Fatal(err)
	}
	if err := nodeRouterSocketDisjoint(sockets[0], local, netip.MustParseAddr("1.1.1.1"), map[netip.Addr]bool{remote: true}); err == nil {
		t.Fatal("backend uses exact TUN source")
	}
	if err := nodeRouterSocketDisjoint(sockets[0], netip.MustParseAddr("172.31.254.1"), remote, map[netip.Addr]bool{remote: true}); err == nil {
		t.Fatal("backend shares service pin")
	}
	if err := nodeRouterSocketDisjoint(sockets[0], netip.MustParseAddr("172.31.254.1"), netip.MustParseAddr("1.1.1.1"), nil); err == nil {
		t.Fatal("unknown backend peer was accepted")
	}
	if _, err := nodeRouterOwnedSockets(append(raw, []byte(row)...), false, map[string]bool{"100": true}); err == nil {
		t.Fatal("duplicate owned inode was accepted")
	}
	if _, err := nodeRouterOwnedSockets([]byte(strings.Replace(string(raw), encode(remote, 443), "invalid", 1)), false, map[string]bool{"100": true}); err == nil {
		t.Fatal("malformed peer was accepted")
	}
	if sockets, err := nodeRouterOwnedSockets(raw, false, map[string]bool{"200": true}); err != nil || len(sockets) != 0 {
		t.Fatal("namespace socket without owned fd was adopted", err)
	}
}

func TestNodeRouterUnconnectedBackendCannotInferIsolation(t *testing.T) {
	socket := nodeRouterBackendSocket{local: netip.MustParseAddrPort("192.0.2.2:30000"), remote: netip.MustParseAddrPort("0.0.0.0:0"), state: "07", inode: "1"}
	if err := nodeRouterSocketDisjoint(socket, netip.MustParseAddr("172.31.254.1"), netip.MustParseAddr("1.1.1.1"), nil); err == nil {
		t.Fatal("unconnected socket gained backend isolation")
	}
	socket.local = netip.MustParseAddrPort("127.0.0.1:18081")
	socket.state = "0A"
	if err := nodeRouterSocketDisjoint(socket, netip.MustParseAddr("172.31.254.1"), netip.MustParseAddr("1.1.1.1"), nil); err != nil {
		t.Fatal("exact loopback listener should remain disjoint", err)
	}
}

func TestNodeRouterBackendOnlyAdmitsOwnedRouteNetlinkControls(t *testing.T) {
	header := "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n"
	row := "0000000000000000 0 42 00000001 0 0 0 2 0 100\n"
	result, err := nodeRouterOwnedRouteNetlink([]byte(header+row), map[string]bool{"100": true})
	if err != nil || len(result) != 1 || !result["100"] {
		t.Fatal("known owned route monitor was unclassified", err)
	}
	if _, err := nodeRouterOwnedRouteNetlink([]byte(header+strings.Replace(row, " 0 42 ", " 15 42 ", 1)), map[string]bool{"100": true}); err == nil {
		t.Fatal("unknown netlink protocol was treated as route monitor")
	}
	if _, err := nodeRouterOwnedRouteNetlink([]byte(header+row+row), map[string]bool{"100": true}); err == nil {
		t.Fatal("duplicate netlink inode accepted")
	}
	if result, err := nodeRouterOwnedRouteNetlink([]byte(header+row), map[string]bool{"200": true}); err != nil || len(result) != 0 {
		t.Fatal("namespace route socket without owned fd adopted", err)
	}
}
