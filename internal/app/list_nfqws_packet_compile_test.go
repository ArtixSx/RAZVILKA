package app

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

func TestNFQWSPacketCompilerRefusesUnsupportedAndEmptyPurposes(t *testing.T) {
	a, b, _ := nfqwsPacketFixture(t)
	listScopeOperation(t, a, func(ctx context.Context) {
		s, err := b.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, model, routes, _ := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
		routes[0].CIDRs = []string{"203.0.113.0/24"}
		type image struct {
			Cfg      config.Config
			Snapshot NFQWSPacketScopeSnapshot
			Services []dataplane.Route
			Paths    map[string]DefaultRoutePath
		}
		base := image{a.Store.Get(), s, routes, map[string]DefaultRoutePath{"listed": model.Paths["listed"]}}
		raw, _ := json.Marshal(base)
		for name, edit := range map[string]func(*image){
			"no positives":               func(i *image) { i.Services = nil },
			"empty destinations":         func(i *image) { i.Services[0].CIDRs = nil },
			"protected-only destination": func(i *image) { i.Services[0].CIDRs = []string{"10.10.0.0/16"} },
			"excluded-only destination":  func(i *image) { i.Services[0].CIDRs = []string{"203.0.113.128/25"} },
			"excluded entire source": func(i *image) {
				i.Cfg.NetworkPolicy.Clients.ExcludedCIDRs = []string{"192.168.1.0/24"}
				i.Cfg.DefaultRouteConsent.Policy.Clients.ExcludedCIDRs = []string{"192.168.1.0/24"}
				i.Cfg.DefaultRouteConsent.Digest = config.DefaultRouteConsentDigest(i.Cfg.DefaultRouteConsent)
				i.Snapshot.Authority.ConsentDigest = i.Cfg.DefaultRouteConsent.Digest
				i.Snapshot.Facts.Intent.ExcludedCIDRs = []string{"192.168.1.0/24"}
			},
			"unknown excluded ID":               func(i *image) { i.Cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"device-legacy"} },
			"MAC negative lost":                 func(i *image) { i.Snapshot.Facts.ExcludedMACs = nil },
			"owned negative lost":               func(i *image) { i.Snapshot.Facts.OwnedMACs = nil },
			"scope revision is config revision": func(i *image) { i.Snapshot.Facts.Intent.Revision++ },
			"policy revision changed":           func(i *image) { i.Snapshot.Facts.Intent.PolicyRevision++ },
			"foreign control":                   func(i *image) { i.Snapshot.Facts.Control.Sequence++ },
			"foreign scope":                     func(i *image) { i.Snapshot.Facts.Home.ID = "Bridge9"; i.Snapshot.Facts.Home.NativeName = "Other" },
			"Guest":                             func(i *image) { i.Snapshot.Facts.Home.Home = false; i.Snapshot.Facts.Home.Guest = true },
			"multiple IPv4 prefixes": func(i *image) {
				i.Snapshot.Facts.IPv4Prefixes = append(i.Snapshot.Facts.IPv4Prefixes, "192.168.2.0/24")
			},
			"source whitelist": func(i *image) {
				v := i.Cfg.Services["listed"]
				v.Sources = []string{"192.168.1.20/32"}
				i.Cfg.Services["listed"] = v
				i.Services[0].Sources = v.Sources
			},
			"source empty intersection": func(i *image) {
				v := i.Cfg.Services["listed"]
				v.Sources = []string{"192.168.2.20/32"}
				i.Cfg.Services["listed"] = v
				i.Services[0].Sources = v.Sources
			},
			"service domain":        func(i *image) { i.Services[0].Domains = []string{"example.com"} },
			"source refs":           func(i *image) { i.Services[0].SourceRefs = []string{"community:other"} },
			"IPv6 destination":      func(i *image) { i.Services[0].CIDRs = []string{"2001:db8::/32"} },
			"mixed destinations":    func(i *image) { i.Services[0].CIDRs = append(i.Services[0].CIDRs, "2001:db8::/32") },
			"other enabled service": func(i *image) { i.Cfg.Services["other"] = config.ServiceState{Enabled: true, Route: "wireguard"} },
			"UDP selected source": func(i *image) {
				p := i.Paths["listed"]
				p.NFQWS.Protocol = "quic"
				p.NFQWS.Traffic[0].Protocol = "udp"
				i.Paths["listed"] = p
			},
			"domain policy rule": func(i *image) {
				i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "domain", Revision: 1, Kind: "exact", Value: "example.com", Action: "direct", Mandatory: true}}
			},
			"service policy rule": func(i *image) {
				i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "service", Revision: 1, Kind: "service", Value: "other", Action: "direct", Mandatory: true}}
			},
			"device-specific IP rule": func(i *image) {
				i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "device", Revision: 1, Kind: "ip", Value: "203.0.113.10", Action: "direct", Mandatory: true, DeviceIDs: []string{"mac-02-00-00-00-00-99"}}}
			},
			"bypass rule": func(i *image) {
				i.Cfg.NetworkPolicy.Rules = []config.NetworkRule{{ID: "bypass", Revision: 1, Kind: "ip", Value: "203.0.113.10", Action: "bypass"}}
			},
			"manual domain exclusion": func(i *image) {
				i.Cfg.NetworkPolicy.Exclusions.Manual = []config.ResourceMatch{{Kind: "exact", Value: "example.com"}}
			},
			"manual service exclusion": func(i *image) {
				i.Cfg.NetworkPolicy.Exclusions.Manual = []config.ResourceMatch{{Kind: "service", Value: "listed"}}
			},
			"DNS mode":  func(i *image) { i.Snapshot.DNSMode = "scoped" },
			"safe mode": func(i *image) { i.Cfg.SafeMode = true },
			"stopped":   func(i *image) { i.Cfg.ServiceControl.Stopped = true },
		} {
			t.Run(name, func(t *testing.T) {
				var i image
				_ = json.Unmarshal(raw, &i)
				edit(&i)
				if c, e := CompileNFQWSIPv4LANPacketPolicy(i.Cfg, i.Snapshot, i.Services, i.Paths, time.Now()); e == nil || c != nil {
					t.Fatal("unsupported purpose silently widened", c, e)
				}
			})
		}
	})
}

func TestNFQWSPacketReviewStableNonceAndCompilationCannotBeReplaced(t *testing.T) {
	a, b, m := nfqwsPacketFixture(t)
	listScopeOperation(t, a, func(c context.Context) {
		compiled := nfqwsPacketCompilation(t, c, a, b)
		s := *compiled.packet
		s.Facts = defaultRoutePacketFactsClone(s.Facts)
		s.Facts.ScopeID = strings.Repeat("a", 32)
		other, err := CompileNFQWSIPv4LANPacketPolicy(a.Store.Get(), s, compiled.packetServices, compiled.snapshot.Paths, time.Now())
		if err != nil || other.Digest() != compiled.Digest() {
			t.Fatal("new read-only lifetime changed stable review", err)
		}
		// Actual Bind still refuses a DTO from a different original lifetime.
		if err = b.BindCompilation(c, other); err == nil {
			t.Fatal("foreign physical nonce replaced original owner")
		}
		compiled.rules[0].Destination = netip.MustParsePrefix("8.8.8.8/32")
		if err = b.BindCompilation(c, compiled); err == nil {
			t.Fatal("replaced compiled tuples admitted")
		}
		compiled = nfqwsPacketCompilation(t, c, a, b)
		if err = b.BindCompilation(c, compiled); err != nil {
			t.Fatal(err)
		}
		if err = b.ScopeCheck(c, compiled.LAN()); err != nil {
			t.Fatal(err)
		}
		// Physical ownership is checked anew without membership. Same scalar
		// epoch/reference restored after a structural error never revives forward.
		m.physicalErr = physicalscope.ErrUnknown
		if _, err = b.Observe(c); err == nil {
			t.Fatal("physical drift accepted")
		}
		m.physicalErr = nil
		if _, err = b.Observe(c); err == nil {
			t.Fatal("poisoned lifetime revived")
		}
	})
}

func TestNFQWSPacketSourceOrUnknownExclusionRefusesBeforePhysicalAcquire(t *testing.T) {
	for _, kind := range []string{"source", "unknown-ID"} {
		t.Run(kind, func(t *testing.T) {
			a, b, _ := nfqwsPacketFixture(t)
			_ = b.Close()
			listScopeOperation(t, a, func(c context.Context) {
				if kind == "source" {
					v := a.Store.Get().Services["listed"]
					v.Sources = []string{"192.168.1.200/32"}
					if err := a.Store.UpdateService("listed", v); err != nil {
						t.Fatal(err)
					}
				} else {
					p := config.CloneNetworkPolicy(a.Store.Get().NetworkPolicy)
					p.Revision++
					p.Clients.ExcludedDeviceIDs = []string{"device-legacy"}
					epoch, err := a.Operations.ReviewControlEpoch(c, a.SelfUpdateFiles.ControlRoot)
					if err != nil {
						t.Fatal(err)
					}
					defer epoch.Close()
					r := epoch.Reference()
					if _, err = a.Store.ApproveDefaultRouteConsent(c, a.Store.Get(), p, nil, r.InstallationID, r.Sequence); err != nil {
						t.Fatal(err)
					}
				}
				called := false
				actual, err := newNFQWSPacketScopeBinding(c, a, func(context.Context, *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
					called = true
					return nil, nil
				})
				if err == nil || actual != nil || called {
					t.Fatal("unsupported selector reached physical acquisition", err, called)
				}
			})
		})
	}
}
