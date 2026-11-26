package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRefreshIncompleteDNSNeverShrinksExistingPolicy(t *testing.T) {
	plan := Plan{Routes: []Route{{ServiceID: "test", Resolved: "warp-wg", Domains: []string{"one.example", "two.example"}, Sources: []string{"192.168.1.50/32"}}}}
	for _, damage := range []string{"timeout", "nodata", "mixed-private", "valid"} {
		t.Run(damage, func(t *testing.T) {
			resolver := func(_ context.Context, h string) ([]netip.Addr, error) {
				if h == "two.example" {
					switch damage {
					case "timeout":
						return nil, errors.New("dns-error")
					case "nodata":
						return nil, nil
					case "mixed-private":
						return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("192.168.1.1")}, nil
					}
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			prefixes, rules, e := resolveRefreshPolicyRules(context.Background(), plan, "warp-wg", resolver)
			if damage == "valid" {
				if e != nil || len(prefixes) != 1 || len(rules) != 1 || rules[0].Source != "192.168.1.50/32" {
					t.Fatal(prefixes, rules, e)
				}
			} else if !errors.Is(e, ErrDNSRefreshIncomplete) || len(prefixes) > 0 || len(rules) > 0 {
				t.Fatal(prefixes, rules, e)
			}
		})
	}
}

type failedRefreshAdapter struct{ *fakeAdapter }

func (a *failedRefreshAdapter) RefreshPolicy(context.Context, Plan) (bool, error) {
	return false, errors.New("secret-host.example token=private")
}
func TestRefreshFailureIsNotReportedAsCheckedAndDoesNotLeakError(t *testing.T) {
	m := New(t.TempDir())
	a := &failedRefreshAdapter{&fakeAdapter{id: "nfqws2"}}
	m.Register(a)
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if e := m.Record(plan); e != nil {
		t.Fatal(e)
	}
	if _, e := m.RefreshCommitted(context.Background()); e == nil {
		t.Fatal("no failure")
	}
	raw, e := os.ReadFile(filepath.Join(m.StateRoot, "latest-policy-refresh.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report PolicyRefresh
	if json.Unmarshal(raw, &report) != nil || report.State != "failed" || strings.Contains(string(raw), "secret-host") || strings.Contains(string(raw), "token=") {
		t.Fatal(string(raw))
	}
}
func TestRefreshAuthorityIsRepeatedAfterResolver(t *testing.T) {
	called := 0
	ctx := WithReviewGuard(context.Background(), func(context.Context) error {
		called++
		if called > 1 {
			return ErrReviewChanged
		}
		return nil
	})
	if checkAddressRefreshAuthority(ctx) != nil {
		t.Fatal("first guard")
	}
	if !errors.Is(checkAddressRefreshAuthority(ctx), ErrReviewChanged) {
		t.Fatal("lost authority")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(checkAddressRefreshAuthority(canceled), context.Canceled) {
		t.Fatal("cancel")
	}
}

// The composed manager/caller authority must terminate, not call itself.
type guardedRefreshAdapter struct {
	*fakeAdapter
	calls *int
}

func (a *guardedRefreshAdapter) RefreshPolicy(ctx context.Context, _ Plan) (bool, error) {
	*a.calls++
	return false, checkAddressRefreshAuthority(ctx)
}
func TestRefreshComposesOriginalCallerGuardWithoutRecursion(t *testing.T) {
	m := New(t.TempDir())
	calls, guards := 0, 0
	a := &guardedRefreshAdapter{&fakeAdapter{id: "nfqws2"}, &calls}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildAt(Input{Revision: 1, Routes: []Route{{ServiceID: "youtube", Resolved: "nfqws2"}}, Engines: []Engine{{ID: "nfqws2", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true, OffloadState: "disabled"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan.State = "committed"
	if err = m.Record(plan); err != nil {
		t.Fatal(err)
	}
	ctx := WithReviewGuard(context.Background(), func(context.Context) error {
		guards++
		if guards > 20 {
			panic("recursive guard")
		}
		return nil
	})
	if _, err = m.RefreshCommitted(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || guards < 3 {
		t.Fatal(calls, guards)
	}
}
