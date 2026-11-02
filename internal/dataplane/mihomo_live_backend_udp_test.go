package dataplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Tuple grammar only: these model objects cannot pass current, observe a
// native child or authorize the production socket scan.
func TestMihomoSOCKSUDPListenerShapeIsExactAndSingle(t *testing.T) {
	role := &mihomoLiveSOCKSUDPListener{profile: components.MihomoLiveProfileReference{SOCKSPort: 18083}}
	role.self = role
	source, pin := netip.MustParseAddr("172.31.23.1"), netip.MustParseAddr("1.1.1.2")
	base := nodeRouterBackendSocket{local: netip.MustParseAddrPort("127.0.0.1:18083"), remote: netip.MustParseAddrPort("0.0.0.0:0"), state: "07", inode: "123"}
	if !role.matches("udp", base, source, pin, false) {
		t.Fatal("exact tuple grammar refused")
	}
	if role.matches("udp", base, source, pin, true) {
		t.Fatal("extra listener inode admitted")
	}
	for _, tc := range []struct {
		name, kind string
		change     func(*nodeRouterBackendSocket)
	}{
		{"wildcard", "udp", func(s *nodeRouterBackendSocket) { s.local = netip.MustParseAddrPort("0.0.0.0:18083") }},
		{"other-loopback", "udp", func(s *nodeRouterBackendSocket) { s.local = netip.MustParseAddrPort("127.0.0.2:18083") }},
		{"foreign-port", "udp", func(s *nodeRouterBackendSocket) { s.local = netip.MustParseAddrPort("127.0.0.1:18084") }},
		{"mapped", "udp", func(s *nodeRouterBackendSocket) { s.local = netip.MustParseAddrPort("[::ffff:127.0.0.1]:18083") }},
		{"ipv6", "udp6", func(s *nodeRouterBackendSocket) { s.local = netip.MustParseAddrPort("[::1]:18083") }},
		{"unknown-state", "udp", func(s *nodeRouterBackendSocket) { s.state = "01" }},
		{"foreign-remote", "udp", func(s *nodeRouterBackendSocket) { s.remote = netip.MustParseAddrPort("1.1.1.1:53") }},
		{"nonzero-remote-port", "udp", func(s *nodeRouterBackendSocket) { s.remote = netip.MustParseAddrPort("0.0.0.0:53") }},
		{"tcp", "tcp", func(*nodeRouterBackendSocket) {}},
		{"unaccounted-inode", "udp", func(s *nodeRouterBackendSocket) { s.inode = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.change(&s)
			if role.matches(tc.kind, s, source, pin, false) {
				t.Fatal("broadened listener shape accepted")
			}
		})
	}
	copy := *role
	if copy.matches("udp", base, source, pin, false) {
		t.Fatal("copied role adopted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if role.current(ctx, 123) == nil {
		t.Fatal("tuple grammar became source/process authority")
	}
	if nodeRouterSocketDisjoint(base, source, pin, nil) == nil {
		t.Fatal("generic unconnected UDP was weakened")
	}
}

func TestMihomoSOCKSUDPListenerOriginalPointerRevocation(t *testing.T) {
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	child, src := &components.MihomoLiveProcess{}, &components.MihomoLiveSource{}
	r := &mihomoLiveResource{adapter: a, child: child, source: src, scope: &executionResourceScope{manager: m}}
	r.self = r
	r.scope.mihomoLive = r
	role := &mihomoLiveSOCKSUDPListener{owner: r, child: child, source: src}
	role.self = role
	if !role.sameOwner() {
		t.Fatal("structural original pointer model refused")
	}
	r.child = &components.MihomoLiveProcess{}
	if role.sameOwner() {
		t.Fatal("foreign child pointer adopted")
	}
	r.child = child
	r.source = &components.MihomoLiveSource{}
	if role.sameOwner() {
		t.Fatal("changed source pointer adopted")
	}
	r.source = src
	r.retired = true
	if role.sameOwner() {
		t.Fatal("retired original source retained role")
	}
	r.retired = false
	r.closed = true
	if role.sameOwner() {
		t.Fatal("closed original source retained role")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if role.current(ctx, 123) == nil {
		t.Fatal("unissued source/process model earned native role")
	}
}
