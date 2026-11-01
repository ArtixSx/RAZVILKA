package app

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

func TestMihomoProbeEnvironmentRechecksCompleteActualDNSSet(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var answers atomic.Value
	first, second, third := netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("93.184.216.35"), netip.MustParseAddr("93.184.216.36")
	answers.Store([]netip.Addr{first, second})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, peer, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buf[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Type == dnsmessage.TypeA {
					for _, ip := range answers.Load().([]netip.Addr) {
						response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: ip.As4()}})
					}
				}
			}
			data, err := response.Pack()
			if err == nil {
				_, _ = listener.WriteTo(data, peer)
			}
		}
	}()
	resolver := net.DefaultResolver
	oldDial, oldPrefer := resolver.Dial, resolver.PreferGo
	resolver.PreferGo = true
	resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", listener.LocalAddr().String())
	}
	defer func() { resolver.Dial, resolver.PreferGo = oldDial, oldPrefer; listener.Close(); <-done }()
	a, _ := awgAPITest(t)
	service := catalog.Service{ID: "video", ProbeURL: "https://example.com/probe", Domains: []string{"example.com"}}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{service}}
	a.FreshProfile = stableNodeProfile
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := newMihomoProbeEnvironment(ctx, a, a.Store.Get(), service)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := env.endpoint(ctx, "edge.example")
	if err != nil || selected != first {
		t.Fatal(selected, err)
	}
	answers.Store([]netip.Addr{second, first})
	if err := env.current(ctx); err != nil {
		t.Fatal("reordering changed exact set", err)
	}
	answers.Store([]netip.Addr{second})
	if err := env.current(ctx); err == nil {
		t.Fatal("removed pinned address accepted")
	}
	answers.Store([]netip.Addr{first, second, third})
	if err := env.current(ctx); err == nil {
		t.Fatal("new DNS member accepted")
	}
	answers.Store([]netip.Addr{first, second})
	manual := []config.ResourceMatch{{Kind: "cidr", Value: second.String() + "/32"}}
	env.cfg, err = a.Store.UpdateResourceExclusions(ctx, env.cfg, &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.current(ctx); err == nil {
		t.Fatal("excluded nonselected DNS member accepted")
	}
	answers.Store([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if _, err := env.resolve(ctx, "edge.example"); err == nil {
		t.Fatal("private DNS member accepted")
	}
}
