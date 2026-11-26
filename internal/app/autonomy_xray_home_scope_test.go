package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestAutonomyXrayHomeChecksRequireOriginalPacketRead(t *testing.T) {
	a, base, model := nfqwsPacketFixture(t)
	cfg := a.Store.Get()
	svc := catalog.Service{ID: "listed", CIDRs: []string{"1.1.1.1/32"}, ProbeURL: "https://1.1.1.1/cdn-cgi/trace"}
	a.Catalog.Services = []catalog.Service{svc}
	p := autonomy.Default()
	p.Enabled, p.SetupComplete = true, true
	s := autonomy.Service{ID: svc.ID, Enabled: true, ExpectedRoute: "auto", AllLAN: true, ManagedLANOnly: true, Definition: autonomyDefinition(svc)}
	a.autonomy.doc.Policy = p
	a.autonomy.doc.Services = map[string]autonomy.Service{s.ID: s}
	listScopeOperation(t, a, func(ctx context.Context) {
		if !a.autonomyHomeXrayShape(cfg, s.ID) {
			t.Fatal("IPv4 Home target with client MAC and CIDR exclusions refused")
		}
		if a.autonomyResourceGuard(ctx, p, s, cfg, svc) == nil {
			t.Fatal("unowned client negatives allowed")
		}
		b := &xrayHomeScopeBinding{base: base}
		b.self = b
		base.homeOwner = b
		h := &autonomyXrayHomeRound{app: a, store: a.Store, original: ctx, spec: s, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), binding: b}
		h.self = h
		c := context.WithValue(ctx, autonomyHomeScopeKey{}, h)
		var escaped context.Context
		reads := model.current
		err := base.use(c, func(held context.Context) error {
			return withAutonomyHomeScopeRead(held, b, func(held context.Context) error {
				escaped = held
				if err := a.autonomyResourceGuard(held, p, s, cfg, svc); err != nil {
					return err
				}
				other := svc
				other.ProbeURL = "https://203.0.113.130/"
				set, err := config.EffectiveConfigResourceExclusions(cfg)
				if err != nil {
					return err
				}
				if autonomyResourceEligibility(held, cfg, s, other, set) == nil {
					t.Fatal("original Home observer waived excluded probe IP")
				}
				return nil
			})
		})
		if err != nil || model.current < reads+2 {
			t.Fatal("original Home packet read", err)
		}
		if a.autonomyResourceGuard(escaped, p, s, cfg, svc) == nil {
			t.Fatal("escaped open read allowed")
		}
		if _, err := a.borrowAutonomyXrayHomeScope(c); err == nil {
			t.Fatal("modeled DTO became physical execution authority")
		}
		foreign := &xrayHomeScopeBinding{base: base}
		foreign.self = foreign
		if foreign.Close() == nil || model.closed != 0 {
			t.Fatal("foreign handle closed original owner")
		}
		if h.close() != nil || h.close() != nil || model.closed != 1 {
			t.Fatal("unborrowed observer not joined", model.closed)
		}
		if a.autonomyResourceGuard(c, p, s, cfg, svc) == nil {
			t.Fatal("closed observer allowed")
		}
	})
}

func TestAutonomyInitialHomeRequiresIdleDataplane(t *testing.T) {
	if !autonomyInitialHomeIdle(dataplane.RuntimeStatus{}) || !autonomyInitialHomeIdle(dataplane.RuntimeStatus{Execution: &dataplane.Execution{State: "rolled-back", RollbackVerified: true}}) {
		t.Fatal("initial and verified rollback must be idle")
	}
	for _, s := range []dataplane.RuntimeStatus{
		{Execution: &dataplane.Execution{State: "committed"}},
		{Execution: &dataplane.Execution{State: "rolled-back"}},
		{CommittedPlan: &dataplane.Plan{}},
		{Recovery: &dataplane.Recovery{State: "recovering"}},
		{Deactivation: &dataplane.Deactivation{State: "stopping"}},
	} {
		if autonomyInitialHomeIdle(s) {
			t.Fatalf("active or uncertain state is not idle: %+v", s)
		}
	}
}
func TestAutonomyXrayHomeOnlyRoutesRepresentableDefinitions(t *testing.T) {
	a, _, _ := nfqwsPacketFixture(t)
	cfg := a.Store.Get()
	spec := autonomy.Service{ID: "listed", AllLAN: true, Enabled: true, ExpectedRoute: "auto"}
	p := autonomy.Default()
	p.PreferredRoutes = []string{"xray"}
	svc := catalog.Service{ID: spec.ID, CIDRs: []string{"1.1.1.1/32"}, ProbeURL: "https://1.1.1.1/cdn-cgi/trace"}
	for _, tc := range []struct {
		name   string
		change func(*catalog.Service)
	}{
		{"domain", func(s *catalog.Service) { s.Domains = []string{"example.org"} }},
		{"dns referenced source", func(s *catalog.Service) { s.SourceRefs = []string{"other"} }},
		{"IPv6", func(s *catalog.Service) { s.CIDRs = []string{"2606:4700:4700::1111/128"} }},
		{"whole subnet", func(s *catalog.Service) { s.CIDRs = []string{"1.1.1.0/24"} }},
		{"private host", func(s *catalog.Service) { s.CIDRs = []string{"192.168.1.1/32"} }},
		{"two addresses", func(s *catalog.Service) { s.CIDRs = []string{"1.1.1.1/32", "1.0.0.1/32"} }},
		{"different service URL", func(s *catalog.Service) { s.ProbeURL = "https://1.0.0.1/cdn-cgi/trace" }},
		{"different required target", func(s *catalog.Service) { s.Probes = []catalog.Probe{{Required: true, URL: "https://1.0.0.1/"}} }},
		{"other TLS port", func(s *catalog.Service) { s.ProbeURL = "https://1.1.1.1:8443/" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := svc
			tc.change(&other)
			a.Catalog.Services = []catalog.Service{other}
			if a.autonomyUsesHomeXray(cfg, p, spec) {
				t.Fatal("unsupported family got an observer")
			}
		})
	}
	a.Catalog.Services = []catalog.Service{svc}
	if !a.autonomyUsesHomeXray(cfg, p, spec) {
		t.Fatal("eligible Home definition lost its observer")
	}
	spec.Sources = []string{"192.168.1.12/32"}
	spec.AllLAN = false
	if a.autonomyUsesHomeXray(cfg, p, spec) {
		t.Fatal("narrow client grant was widened to Home")
	}
}
func autonomyHomeCandidateFixture(t *testing.T) (*App, *nfqwsPacketModel) {
	t.Helper()
	original, previous, model := nfqwsPacketFixture(t)
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}
	if err := original.CloseDefaultConsent(); err != nil {
		t.Fatal(err)
	}
	nodesPath := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(nodesPath, 0o700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodesPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodes.Close() })
	a := &App{Store: original.Store, SelfUpdateFiles: original.SelfUpdateFiles, Nodes: nodes, FreshProfile: original.FreshProfile}
	if err := a.ConfigureDefaultConsent(original.defaultConsent.configPath, nodesPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	return a, model
}

func TestAutonomyInitialHomePublicNodeCandidatePreservesConsent(t *testing.T) {
	a, model := autonomyHomeCandidateFixture(t)
	ctx := context.Background()
	const sourceID = "feed-home-test"
	snapshot, err := a.Nodes.Import(ctx, nodestore.Source{ID: sourceID, Kind: "subscription"}, "vless://123e4567-e89b-12d3-a456-426614174000@public-page.example:443?security=tls", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	var route string
	for _, n := range snapshot.Nodes {
		for _, origin := range n.Origins {
			if origin.SourceID == sourceID {
				route = "xray:" + n.ID
			}
		}
	}
	if route == "" {
		t.Fatal("missing public source binding")
	}
	svc := catalog.Service{ID: "listed", CIDRs: []string{"1.1.1.1/32"}, ProbeURL: "https://1.1.1.1/cdn-cgi/trace"}
	a.Catalog.Services = []catalog.Service{svc}
	if err := a.Store.UpdateService(svc.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, a, func(c context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(c, a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		before := a.Store.Get()
		policy := config.CloneNetworkPolicy(before.NetworkPolicy)
		policy.Revision++
		ref := epoch.Reference()
		if _, err := a.Store.ApproveDefaultRouteConsent(c, before, policy, nil, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
	})
	cfg := a.Store.Get()
	if err := a.loadAutonomy(ctx); err != nil {
		t.Fatal(err)
	}
	p := autonomy.Default()
	p.Enabled, p.SetupComplete, p.AllLAN, p.ManagedLANOnly, p.Revision = true, true, true, true, 1
	p.PreferredRoutes = []string{"xray"}
	p.SourceIDs = []string{sourceID}
	s := autonomy.Service{ID: svc.ID, Enabled: true, AllLAN: true, ManagedLANOnly: true, ExpectedRoute: "auto", DraftFingerprint: autonomyDraftFingerprint(cfg.Services[svc.ID]), Definition: autonomyDefinition(svc)}
	a.autonomy.doc.Policy = p
	a.autonomy.doc.Services[s.ID] = s
	if err := a.persistAutonomyLocked(ctx); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, a, func(c context.Context) {
		base, err := newNFQWSPacketScopeBinding(c, a, func(ctx context.Context, b *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
			intent, err := b.intent(ctx)
			if err != nil {
				return nil, err
			}
			model.facts.Intent, model.facts.Control = intent, b.control.Reference()
			model.b = b
			return model, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		b := &xrayHomeScopeBinding{base: base}
		b.self = b
		base.homeOwner = b
		h := &autonomyXrayHomeRound{app: a, store: a.Store, original: c, spec: s, policy: config.CloneNetworkPolicy(cfg.NetworkPolicy), consent: config.CloneDefaultRouteConsent(cfg.DefaultRouteConsent), binding: b}
		h.self = h
		defer h.close()
		owned := context.WithValue(c, autonomyHomeScopeKey{}, h)
		err = base.use(owned, func(held context.Context) error {
			return withAutonomyHomeScopeRead(held, b, func(held context.Context) error {
				candidate, err := a.xrayAutonomyCandidate(held, p, s, cfg, base.snapshot.NetworkID, route)
				if err != nil {
					return err
				}
				if !candidate.initialHome || candidate.planned.AppliedNetworkPolicy != nil || !reflect.DeepEqual(candidate.before, cfg) || !reflect.DeepEqual(cfg, a.Store.Get()) || !reflect.DeepEqual(candidate.planned.NetworkPolicy, cfg.NetworkPolicy) || !reflect.DeepEqual(candidate.planned.DefaultRouteConsent, cfg.DefaultRouteConsent) || candidate.planned.Services[s.ID].Route != route {
					t.Fatal("candidate changed or fabricated applied Home policy")
				}
				var checks int
				a.NodeHistoryWriteGuard = func(context.Context, int) error { return nil }
				a.NodeCheckers = map[string]dataplane.NodeChecker{"xray": jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
					checks++
					return d10Result(req, "xray", true), nil
				})}
				id := strings.TrimPrefix(route, "xray:")
				run := func(r autonomy.Runtime) autonomy.Runtime {
					snap, err := a.Nodes.Snapshot(held, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					return a.runAutonomyFirstUsable(held, p, s, r, cfg, svc, "xray", base.snapshot.NetworkID, "", []string{id}, snap.Nodes, nil)
				}
				r := run(autonomy.Runtime{})
				if r.State != homeServiceCheckedState || r.Message != homeServiceCheckedMessage || checks != 1 ||
					!slices.Equal(r.Reserves, []string{id}) || r.ReserveCheckedAt.IsZero() || !r.CheckedAt.IsZero() ||
					len(r.Switches) != 0 || r.Search.Halted || !reflect.DeepEqual(cfg, a.Store.Get()) {
					t.Fatalf("isolated check: state=%s message=%s calls=%d reserves=%v", r.State, r.Message, checks, r.Reserves)
				}
				if !a.autonomyRuntime(p.Revision, s.ID, r) {
					t.Fatal("failed to publish isolated result")
				}
				again := run(r)
				if again.State != homeServiceCheckedState || again.Message != homeServiceCheckedMessage || checks != 1 || len(again.Switches) != 0 ||
					!reflect.DeepEqual(cfg, a.Store.Get()) {
					t.Fatal("fresh isolated evidence triggered application or repeat", again.State, checks)
				}
				snap, err := a.Nodes.Snapshot(held, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				overdue := again.ReserveCheckedAt.Add(time.Duration(p.ReserveSeconds) * time.Second)
				if until := a.autonomyHomeReserveUntil(held, p, s, again, []string{id}, snap.Nodes, base.snapshot.NetworkID, overdue); !until.IsZero() {
					t.Fatal("expired reserve was displayed as checked", until)
				}
				if _, err := a.Nodes.SetDisabled(held, id, true, time.Now()); err != nil {
					t.Fatal(err)
				}
				revoked := run(again)
				if revoked.State == homeServiceCheckedState || len(revoked.Reserves) != 0 || !revoked.ReserveCheckedAt.IsZero() || checks != 1 || len(revoked.Switches) != 0 {
					t.Fatal("disabled reserve retained verification", revoked.State)
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestHomePeerReserveOrdersOnlyUntriedPublicCandidate(t *testing.T) {
	a, _ := autonomyHomeCandidateFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const network = "wan-0123456789ab"
	const source = "feed-vlessforu"
	a.Catalog = catalog.WithWebDefaults(catalog.Catalog{})
	cfg := a.Store.Get()
	spec := func(id string) autonomy.Service {
		svc, ok := a.autonomyService(id)
		if !ok {
			t.Fatal("missing service", id)
		}
		cfg.Services[id] = config.ServiceState{Enabled: true, Route: "auto"}
		return autonomy.Service{ID: id, Enabled: true, AllLAN: true, ManagedLANOnly: true, ExpectedRoute: "auto", Definition: autonomyDefinition(svc)}
	}
	telegram, discord := spec("telegram-web"), spec("discord-web")
	p := autonomy.Default()
	p.SetupComplete, p.Enabled, p.AllLAN, p.ManagedLANOnly, p.Revision = true, true, true, true, 1
	p.SourceIDs = []string{source}
	p.PreferredRoutes = []string{"xray"}
	snap, err := a.Nodes.Import(ctx, nodestore.Source{ID: source, Kind: "community"},
		"vless://123e4567-e89b-12d3-a456-426614174000@a.example.test:443?security=tls\nvless://123e4567-e89b-12d3-a456-426614174001@b.example.test:443?security=tls", now.Add(-time.Minute), time.Hour, false)
	if err != nil || len(snap.Nodes) != 2 {
		t.Fatal("public nodes", err, len(snap.Nodes))
	}
	first, known := snap.Nodes[0].ID, snap.Nodes[1].ID
	at := now.Add(-time.Second)
	proof := nodestore.CheckRecord{ProbeID: "peer-check", ServiceID: telegram.ID, NetworkProfile: network, RoutePathID: "xray:" + known, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: at, ExpiresAt: now.Add(time.Minute)}
	if _, err = a.Nodes.RecordCheck(ctx, known, proof, now); err != nil {
		t.Fatal(err)
	}
	snap, err = a.Nodes.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	version, ok := a.autonomySearchVersion(p, telegram, "xray", network, cfg)
	if !ok {
		t.Fatal("Home web check not admitted")
	}
	receipt := autonomy.Runtime{State: homeServiceCheckedState, Search: &autonomy.Traversal{Version: version}, Reserves: []string{known}, ReserveConfigRevision: cfg.Revision, ReserveCheckedAt: at, ReserveValidUntil: proof.ExpiresAt}
	doc := autonomyDocument{Policy: p, Services: map[string]autonomy.Service{telegram.ID: telegram, discord.ID: discord}, Runtime: map[string]autonomy.Runtime{telegram.ID: receipt}}
	eligible := []string{first, known}
	for _, tc := range []string{"fresh", "owner-first", "consumed", "cooldown", "changed-network", "expired", "disabled", "revised", "tried", "other-origin", "exact-first"} {
		t.Run(tc, func(t *testing.T) {
			target := autonomy.Runtime{Search: &autonomy.Traversal{Ordered: slices.Clone(eligible)}}
			seenAt := now
			wan := network
			revision := cfg.Revision
			rows := slices.Clone(snap.Nodes)
			switch tc {
			case "consumed":
				target.Search.Ordered = []string{known, first}
				target.Search.Cursor = 1
			case "cooldown":
				target.CandidateFailures = []autonomy.CandidateFailure{{NodeID: known}}
			case "changed-network":
				wan = "wan-999999999999"
			case "expired":
				seenAt = proof.ExpiresAt
			case "revised":
				revision++
			case "disabled":
				rows[1].Disabled = true
			case "tried":
				previous := proof
				previous.ServiceID = discord.ID
				previous.Verdict = "ERROR"
				rows[1].Health.History = append(slices.Clone(rows[1].Health.History), previous)
			case "other-origin":
				rows[1].Origins = []nodestore.Origin{{SourceID: "manual", ReceivedAt: at, ExpiresAt: proof.ExpiresAt}}
			case "exact-first":
				current := proof
				current.ServiceID = discord.ID
				current.ProbeID = "exact-check"
				current.RoutePathID = "xray:" + first
				if _, err := a.Nodes.RecordCheck(ctx, first, current, now); err != nil {
					t.Fatal(err)
				}
			}
			hints := homeQueueHints(doc, discord.ID, revision, seenAt)
			round := context.WithValue(ctx, homeQueueHintsKey{}, hints)
			peers := a.homeQueuePeerNodes(round, p, discord, target, cfg, "xray", wan, eligible, rows, seenAt)
			promote := tc == "fresh" || tc == "owner-first" || tc == "exact-first"
			if peers[known] != promote {
				t.Fatalf("peer hint=%v", peers)
			}
			before := slices.Clone(target.Search.Ordered)
			a.prioritizeAutonomyFreshProofs(round, p, discord, &target, "xray", wan, eligible, seenAt, peers)
			if tc == "owner-first" {
				if _, err := a.prioritizeAutonomySources(round, p, &target, now, map[string]bool{first: true}); err != nil {
					t.Fatal(err)
				}
			}
			if tc == "fresh" {
				before = []string{known, first}
			}
			if !slices.Equal(before, target.Search.Ordered) {
				t.Fatal("order", target.Search.Ordered)
			}
			if len(target.Reserves) != 0 || target.State != "" || cfg.AppliedServices[discord.ID].Enabled {
				t.Fatal("peer check supplied target confirmation")
			}
			if _, err := a.Nodes.ResolveRouteForEngine(round, "xray", known, discord.ID, wan, "", time.Time{}, seenAt); err == nil {
				t.Fatal("peer used as Discord proof")
			}
		})
	}
}
