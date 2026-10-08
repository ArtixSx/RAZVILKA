package usquediag

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
)

type ownedProbeTargetFixture struct {
	ctx        context.Context
	store      *config.Store
	review     *defaultconsent.Review
	owner      *defaultconsent.Owner
	release    func()
	configured bool
}

// This fixture retains the real original Store/Gate/control owner and performs
// only local file-model approval. Resolver/CONNECT results are in-memory; it
// does not start USQUE, open a socket, accept a client or activate a route.
func newOwnedProbeTargetFixture(t *testing.T, manual []config.ResourceMatch) *ownedProbeTargetFixture {
	t.Helper()
	base := t.TempDir()
	configPath, nodeRoot, controlRoot := filepath.Join(base, "config.json"), filepath.Join(base, "nodes"), filepath.Join(base, "control")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nodeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	f := &ownedProbeTargetFixture{store: store, release: release, configured: true}
	owner, err := defaultconsent.NewOwner(ctx, gate, &f.store, &nodes, configPath, nodeRoot, controlRoot, func() bool { return f.configured })
	if err != nil {
		t.Fatal(err)
	}
	f.owner = owner
	t.Cleanup(func() { _ = owner.Close() })
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	grants := []config.DefaultRouteGrant{{Resolved: "usque", ProviderClass: "cloudflare", ProviderID: "usque"}}
	if _, err := owner.Approve(ctx, store.Get(), policy, grants); err != nil {
		t.Fatal(err)
	}
	if manual != nil {
		after, err := store.UpdateResourceExclusions(ctx, store.Get(), &manual, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy = config.CloneNetworkPolicy(after.NetworkPolicy)
		policy.Revision++
		if _, err := owner.Approve(ctx, store.Get(), policy, grants); err != nil {
			t.Fatal(err)
		}
	}
	f.review, err = owner.Review(ctx, "usque")
	if err != nil {
		t.Fatal(err)
	}
	f.ctx = WithOwnedProbeTargetReview(ctx, f.review)
	return f
}

func TestOwnedProbeTargetOriginalContextSurvivesDetachedDial(t *testing.T) {
	f := newOwnedProbeTargetFixture(t, nil)
	request, cancel := ownedOperationRequestContext(f.ctx, time.Second)
	defer cancel()
	operation, err := ownedOperationDialContext(context.WithoutCancel(request))
	if err != nil || checkOwnedProbeTarget(operation, "www.cloudflare.com", []netip.Addr{netip.MustParseAddr("1.1.1.1")}) != nil {
		t.Fatal("original concrete owner/Gate context lost", err)
	}
	if WithOwnedProbeTargetReview(nil, f.review) != nil {
		t.Fatal("nil context fabricated")
	}
	if err := checkOwnedProbeTarget(WithOwnedProbeTargetReview(f.ctx, nil), "www.cloudflare.com", nil); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) {
		t.Fatal("nil replacement retained old authority", err)
	}
}

func TestOwnedDialPublicRefusesMissingForeignReleasedAndStaleOwnerBeforeDNS(t *testing.T) {
	for _, kind := range []string{"missing", "nil", "zero", "foreign", "released", "config", "configured", "closed"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnedProbeTargetFixture(t, nil)
			ctx := f.ctx
			switch kind {
			case "missing":
				ctx = context.Background()
			case "nil":
				ctx = WithOwnedProbeTargetReview(ctx, nil)
			case "zero":
				ctx = WithOwnedProbeTargetReview(ctx, &defaultconsent.Review{})
			case "foreign":
				foreign := newOwnedProbeTargetFixture(t, nil)
				ctx = WithOwnedProbeTargetReview(foreign.ctx, f.review)
			case "released":
				f.release()
			case "config":
				if err := f.store.UpdateService("changed", config.ServiceState{Route: "direct"}); err != nil {
					t.Fatal(err)
				}
			case "configured":
				f.configured = false
			case "closed":
				if err := f.owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			resolved, connected := 0, 0
			conn, err := ownedDialPublic(ctx, netip.MustParseAddrPort("127.0.0.1:18081"), "example.com:443", &probeSockets{},
				func(context.Context, string) ([]netip.Addr, error) {
					resolved++
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error) {
					connected++
					return &ownedDNSFixtureConn{}, nil, nil
				})
			if conn != nil || !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) || resolved != 0 || connected != 0 {
				t.Fatalf("unowned leaf reached DNS/CONNECT: %v %v %d %d", conn, err, resolved, connected)
			}
		})
	}
}

func TestOwnedDialPublicExclusionsCoverHostnameAndEveryPublicPin(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		manual       []config.ResourceMatch
		pins         []netip.Addr
		wantResolve  int
	}{
		{"hostname before DNS", "WWW.Cloudflare.COM.:443", []config.ResourceMatch{{Kind: "exact", Value: "www.cloudflare.com"}}, nil, 0},
		{"suffix before DNS", "trace.cloudflare.com:443", []config.ResourceMatch{{Kind: "suffix", Value: "cloudflare.com"}}, nil, 0},
		{"nonselected v4", "example.com:443", []config.ResourceMatch{{Kind: "ip", Value: "1.0.0.1"}}, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}, 1},
		{"nonselected v6", "example.com:443", []config.ResourceMatch{{Kind: "cidr", Value: "2606:4700::/32"}}, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}, 1},
		{"literal v4", "1.1.1.1:443", []config.ResourceMatch{{Kind: "ip", Value: "1.1.1.1"}}, nil, 0},
		{"literal v6", "[2606:4700:4700::1111]:443", []config.ResourceMatch{{Kind: "cidr", Value: "2606:4700::/32"}}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOwnedProbeTargetFixture(t, tc.manual)
			resolved, connected := 0, 0
			conn, err := ownedDialPublic(f.ctx, netip.MustParseAddrPort("127.0.0.1:18081"), tc.target, &probeSockets{},
				func(context.Context, string) ([]netip.Addr, error) { resolved++; return tc.pins, nil },
				func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error) {
					connected++
					return &ownedDNSFixtureConn{}, nil, nil
				})
			if conn != nil || !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) || resolved != tc.wantResolve || connected != 0 {
				t.Fatalf("excluded target reached CONNECT: %v %v %d %d", conn, err, resolved, connected)
			}
		})
	}
}

func TestOwnedDialPublicConfigRevocationDuringResolverOrCONNECT(t *testing.T) {
	for _, phase := range []string{"resolve", "connect"} {
		t.Run(phase, func(t *testing.T) {
			f := newOwnedProbeTargetFixture(t, nil)
			revoke := func() {
				updated := make(chan error, 1)
				go func() { updated <- f.store.UpdateService("changed", config.ServiceState{Route: "direct"}) }()
				select {
				case err := <-updated:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Store lock retained over resolver/CONNECT")
				}
			}
			connected := 0
			fake := &ownedDNSFixtureConn{}
			conn, err := ownedDialPublic(f.ctx, netip.MustParseAddrPort("127.0.0.1:18081"), "example.com:443", &probeSockets{},
				func(context.Context, string) ([]netip.Addr, error) {
					if phase == "resolve" {
						revoke()
					}
					return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
				},
				func(context.Context, netip.AddrPort, byte, []byte, *probeSockets) (net.Conn, []byte, error) {
					connected++
					revoke()
					return fake, nil, nil
				})
			wantConnect := 0
			if phase == "connect" {
				wantConnect = 1
			}
			if conn != nil || !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) || connected != wantConnect || fake.closed != (phase == "connect") {
				t.Fatalf("stale leaf accepted or not closed: %v %v %d closed%v", conn, err, connected, fake.closed)
			}
		})
	}
}

func TestOwnedDoHChecksBootstrapHostnameLiteralAndClosingOwner(t *testing.T) {
	for _, kind := range []string{"success", "domain", "literal", "missing", "changed"} {
		t.Run(kind, func(t *testing.T) {
			var manual []config.ResourceMatch
			if kind == "domain" {
				manual = []config.ResourceMatch{{Kind: "exact", Value: "cloudflare-dns.com"}}
			}
			if kind == "literal" {
				manual = []config.ResourceMatch{{Kind: "ip", Value: "1.1.1.1"}}
			}
			f := newOwnedProbeTargetFixture(t, manual)
			ctx := f.ctx
			if kind == "missing" {
				ctx = context.Background()
			}
			fake, connected := &ownedDNSFixtureConn{}, 0
			conn, err := ownedDialDoH(ctx, netip.MustParseAddrPort("127.0.0.1:18081"), &probeSockets{},
				func(_ context.Context, _ netip.AddrPort, cmd byte, address []byte, _ *probeSockets) (net.Conn, []byte, error) {
					connected++
					want, _ := ownedSOCKSAddress("1.1.1.1", 443)
					if cmd != 1 || !bytes.Equal(address, want) {
						t.Fatal("bootstrap literal moved")
					}
					if kind == "changed" {
						f.configured = false
					}
					return fake, nil, nil
				})
			wantConnected := kind == "success" || kind == "changed"
			if (err == nil) != (kind == "success") || (conn != nil) != (kind == "success") || (connected == 1) != wantConnected || fake.closed != (kind == "changed") {
				t.Fatalf("bootstrap admission/closing: %v %v %d %v", conn, err, connected, fake.closed)
			}
			if kind == "domain" || kind == "literal" {
				if !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) {
					t.Fatal("exclusion lost", err)
				}
			}
			if conn != nil {
				conn.Close()
			}
		})
	}
}

func TestOwnedNetworkKnownExcludedTargetsAndMissingOwnerRefusePreflight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		manual []config.ResourceMatch
	}{
		{"trace", []config.ResourceMatch{{Kind: "exact", Value: "www.cloudflare.com"}}},
		{"DoH domain", []config.ResourceMatch{{Kind: "exact", Value: "cloudflare-dns.com"}}},
		{"DoH IP", []config.ResourceMatch{{Kind: "ip", Value: "1.1.1.1"}}},
		{"service", []config.ResourceMatch{{Kind: "exact", Value: "example.com"}}},
		{"UDP", []config.ResourceMatch{{Kind: "ip", Value: "1.0.0.1"}}},
		{"missing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOwnedProbeTargetFixture(t, tc.manual)
			ctx := f.ctx
			if tc.name == "missing" {
				ctx = context.Background()
			}
			request := OwnedNetworkRequest{SOCKSAddress: "127.0.0.1:18081", Services: []OwnedServiceProbe{{ID: "fixture", URL: "https://example.com/proof"}}, UDP: &OwnedUDPProbe{Target: netip.MustParseAddrPort("1.0.0.1:443")}}
			proof, err := probeOwnedNetwork(ctx, request)
			want := defaultconsent.ErrProbeTargetExcluded
			if tc.name == "missing" {
				want = defaultconsent.ErrProbeTargetUnknown
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(proof, OwnedApplicationProof{}) {
				t.Fatal("preflight accepted target or emitted proof", err, proof)
			}
		})
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := probeOwnedSOCKSUDP(ctx, netip.MustParseAddrPort("127.0.0.1:18081"), netip.MustParseAddrPort("1.0.0.1:443"), &probeSockets{}); !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) {
			t.Fatal("UDP without original owner reached socket", err)
		}
	}
}

func TestOwnedProbeExclusionClassificationSurvivesHTTPAndDNSWithoutPrivateErrorText(t *testing.T) {
	for _, cause := range []error{defaultconsent.ErrProbeTargetExcluded, defaultconsent.ErrProbeTargetUnknown} {
		client := &http.Client{Transport: ownedMemoryRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.Join(cause, errors.New("private-marker"))
		})}
		_, httpErr := ownedHTTPSBody(context.Background(), client, "https://example.com/proof", "", 256, true)
		_, dnsErr := ownedResolvePublic(context.Background(), "example.com", func(ctx context.Context, query []byte) ([]byte, error) { return ownedDoHExchange(ctx, client, query) })
		for _, err := range []error{httpErr, dnsErr} {
			if !errors.Is(err, cause) || strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), "https://") {
				t.Fatal("exclusion outcome lost or private error leaked", err)
			}
		}
	}
}

func TestOwnedDNSChecksValidatedAliasesAndNonselectedAddressRecords(t *testing.T) {
	for _, tc := range []struct {
		name, kind, value string
	}{
		{"allowed", "", ""},
		{"CNAME domain", "exact", "edge.example.com"},
		{"terminal IP", "ip", "1.1.1.1"},
		{"glue other family", "cidr", "2606:4700::/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var manual []config.ResourceMatch
			if tc.kind != "" {
				manual = []config.ResourceMatch{{Kind: tc.kind, Value: tc.value}}
			}
			f := newOwnedProbeTargetFixture(t, manual)
			query := ownedDNSFixtureQuery(t, dnsmessage.TypeA)
			message := ownedDNSFixtureResponse(t, query)
			message.Answers = []dnsmessage.Resource{ownedDNSFixtureAlias("example.com.", "edge.example.com."), ownedDNSFixtureAddress("edge.example.com.", "1.1.1.1")}
			message.Additionals = []dnsmessage.Resource{ownedDNSFixtureAddress("ns.example.com.", "2606:4700:4700::1111")}
			response := ownedDNSFixturePack(t, message)
			err := checkOwnedDNSProbeAnswer(f.ctx, query, response)
			if tc.kind == "" && err != nil || tc.kind != "" && !errors.Is(err, defaultconsent.ErrProbeTargetExcluded) {
				t.Fatal("validated DNS negative lost", err)
			}
			// Malformed packets never become policy observations.
			response[0] ^= 1
			if err := checkOwnedDNSProbeAnswer(f.ctx, query, response); !errors.Is(err, errOwnedNetworkDNS) || errors.Is(err, defaultconsent.ErrProbeTargetExcluded) {
				t.Fatal("unvalidated DNS accepted for exclusions", err)
			}
		})
	}
}
