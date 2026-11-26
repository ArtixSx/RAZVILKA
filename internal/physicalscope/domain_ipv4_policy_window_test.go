package physicalscope

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type domainPolicyTestMonitor struct {
	checkpoint func(context.Context) error
	release    func() error
}

func (m domainPolicyTestMonitor) quiet(ctx context.Context) error { return m.checkpoint(ctx) }
func (m domainPolicyTestMonitor) close() error                    { return m.release() }

func TestDomainIPv4ForwardedPolicyWindowKeepsOneBoundedOriginalRead(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 92}
	query := DomainIPv4PolicyLookupQuery{Source: netip.MustParseAddr("192.168.71.2"), Destination: netip.MustParseAddr("93.184.216.34"), IngressIndex: 12, Mark: 42}
	want := []string{"identity-open", "subscribe", "rules", "routes", "links", "lookup", "identity-close", "notification-read", "release"}
	for _, name := range []string{"stable", "changed-then-restored", "queue-loss", "close-failed", "canceled-while-reading", "canceled-while-releasing", "namespace-changed", "wrong-namespace", "local-output", "unbounded", "missing-egress", "wrong-mark", "missing-table"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			var calls []string
			current := func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				calls = append(calls, "identity-open")
				actual := id
				if name == "wrong-namespace" {
					actual.Inode++
				}
				err := use(c, actual)
				calls = append(calls, "identity-close")
				if name == "namespace-changed" {
					return errors.Join(err, ErrUnknown)
				}
				return err
			}
			sources := domainIPv4PolicyWindowSources{
				open: func(context.Context) (domainIPv4PolicyWindowMonitor, error) {
					calls = append(calls, "subscribe")
					return domainPolicyTestMonitor{
						checkpoint: func(context.Context) error {
							calls = append(calls, "notification-read")
							switch name {
							case "changed-then-restored":
								return ErrDomainIPv4PolicyWindowChanged
							case "queue-loss":
								return errors.New("netlink receive loss")
							case "canceled-while-reading":
								cancel()
							}
							return nil
						},
						release: func() error {
							calls = append(calls, "release")
							if name == "close-failed" {
								return errors.New("cannot release original subscription")
							}
							if name == "canceled-while-releasing" {
								cancel()
							}
							return nil
						},
					}, nil
				},
				dump: func(c context.Context, kind uint16, family byte) ([]message, error) {
					limit, finite := c.Deadline()
					if !finite || limit.After(deadline) {
						t.Fatal("dump exceeded the caller's deadline")
					}
					rules, routes, links := domainPolicyInventoryModel()
					switch {
					case kind == 34 && family == 2:
						calls = append(calls, "rules")
						return rules, nil
					case kind == 26 && family == 2:
						calls = append(calls, "routes")
						return routes, nil
					case kind == 18 && family == 0:
						calls = append(calls, "links")
						return links, nil
					default:
						t.Fatalf("unexpected dump ABI %d/%d", kind, family)
						return nil, ErrUnknown
					}
				},
				lookup: func(c context.Context, original DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error) {
					calls = append(calls, "lookup")
					limit, finite := c.Deadline()
					if original != query || !finite || limit.After(deadline) {
						t.Fatal("lookup substituted original input or exceeded its deadline")
					}
					got := DomainIPv4PolicyLookup{Source: query.Source, Destination: query.Destination, IngressIndex: 12, EgressIndex: 13, Table: 10037, Mark: query.Mark}
					switch name {
					case "missing-egress":
						got.EgressIndex = 15
					case "wrong-mark":
						got.Mark++
					case "missing-table":
						got.Table++
					}
					return got, nil
				},
			}
			request := query
			if name == "local-output" {
				request.IngressIndex = 0
			}
			if name == "unbounded" {
				ctx = context.Background()
			}
			got, err := readDomainIPv4ForwardedPolicyWindow(ctx, id, request, current, sources)
			if name == "stable" {
				if err != nil || got.Identity != id || len(got.Inventory.Rules) != 7 || got.Lookup.Table != 10037 || !slices.Equal(calls, want) {
					t.Fatalf("original policy/lookup window was lost: %+v %v calls=%v", got, err, calls)
				}
				return
			}
			if !errors.Is(err, ErrUnknown) || !reflect.DeepEqual(got, DomainIPv4ForwardedPolicyWindow{}) {
				t.Fatalf("partial result escaped: %+v %v", got, err)
			}
			switch name {
			case "changed-then-restored":
				if !errors.Is(err, ErrDomainIPv4PolicyWindowChanged) {
					t.Fatalf("change reason was lost: %v", err)
				}
			case "canceled-while-reading", "canceled-while-releasing":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation reason was lost: %v", err)
				}
			}
			expectedCalls := want
			switch name {
			case "local-output", "unbounded":
				expectedCalls = nil
			case "wrong-namespace":
				expectedCalls = []string{"identity-open", "identity-close"}
			case "namespace-changed":
				expectedCalls = append(slices.Clone(want[:7]), "release")
			}
			if !slices.Equal(calls, expectedCalls) {
				t.Fatalf("wrong subscription lifecycle: got %v, want %v", calls, expectedCalls)
			}
		})
	}
}
